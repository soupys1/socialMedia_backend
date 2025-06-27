require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const fileUpload = require('express-fileupload');
const path = require('path');
const { createClient } = require('@supabase/supabase-js');

// Environment variable validation
const requiredEnvVars = ['SUPABASE_URL', 'SUPABASE_ANON_KEY'];
for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    console.error(`Missing required environment variable: ${envVar}`);
    process.exit(1);
  }
}

const app = express();
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);

// Enhanced CORS configuration for cross-site cookies
app.use(cors({
  origin: [
    'https://social-media-frontend-black-five.vercel.app',
    'http://localhost:3000',
    'http://localhost:5173',
    'http://127.0.0.1:3000',
    'http://127.0.0.1:5173'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

app.use(bodyParser.json());
app.use(cookieParser());
app.use(fileUpload({
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  abortOnLimit: true,
}));
app.disable('x-powered-by');

// Utility function to delete files from Supabase Storage
const deleteStorageFiles = async (bucket, paths) => {
  if (paths.length === 0) return;
  const { error } = await supabase.storage.from(bucket).remove(paths);
  if (error) throw error;
};

// Enhanced authentication middleware
const authenticate = async (req, res, next) => {
  try {
    // Support both cookie and Authorization header
    let token = req.cookies.token;
    if (!token && req.headers.authorization) {
      const authHeader = req.headers.authorization;
      if (authHeader.startsWith('Bearer ')) {
        token = authHeader.substring(7);
      }
    }

    if (!token) {
      console.log('No token found in cookies or headers');
      return res.status(401).json({ error: 'No token provided' });
    }

    console.log('Token found:', token.substring(0, 20) + '...');

    const { data: { user }, error } = await supabase.auth.getUser(token);
    if (error || !user) {
      console.log('Token validation error:', error?.message);
      return res.status(401).json({ error: 'Invalid or expired token' });
    }

    console.log('User authenticated:', user.id);
    req.user = user;
    // Attach a Supabase client with the user's token for RLS
    req.supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY, {
      global: { headers: { Authorization: `Bearer ${token}` } }
    });
    next();
  } catch (error) {
    console.error('Authentication error:', error.message);
    res.status(401).json({ error: 'Authentication failed' });
  }
};

// Helper function to validate profile picture URL
const validateProfilePicture = (profilePicture) => {
  if (!profilePicture || typeof profilePicture !== 'string') return null;
  if (profilePicture === 'profile:1' || !profilePicture.startsWith('http')) return null;
  return profilePicture;
};

// Auth Routes
app.post('/api/signup', async (req, res) => {
  const { username, password, firstName, lastName, email } = req.body;
  if (!username || !password || !firstName || !lastName || !email) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  try {
    // Check for existing username or email in the users table
    const { data: existingUsers, error: checkError } = await supabase
      .from('users')
      .select('id')
      .or(`username.eq.${username},email.eq.${email}`);

    if (checkError) {
      console.error('Error checking existing user:', checkError);
      throw checkError;
    }

    if (existingUsers && existingUsers.length > 0) {
      return res.status(400).json({ error: 'Username or email already in use' });
    }

    // Sign up user with Supabase Auth only
    // The database trigger will automatically create the user profile
    const { data: authUser, error: authError } = await supabase.auth.signUp({
      email,
      password,
      options: {
        data: { 
          username, 
          first_name: firstName, 
          last_name: lastName 
        },
      },
    });

    if (authError) {
      console.error('Supabase Auth signup error:', authError);
      throw authError;
    }

    if (!authUser.user) {
      throw new Error('No user returned from Supabase Auth');
    }

    console.log('User created successfully in Supabase Auth:', authUser.user.id);
    res.status(201).json({ 
      message: 'User created successfully',
      user: {
        id: authUser.user.id,
        email: authUser.user.email
      }
    });
  } catch (error) {
    console.error('Signup error:', error.message);
    
    // Provide more specific error messages
    if (error.message.includes('already registered')) {
      return res.status(400).json({ error: 'Email already registered' });
    }
    if (error.message.includes('password')) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    
    res.status(500).json({ error: 'Failed to sign up. Please try again.' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  try {
    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password,
    });

    if (error) {
      console.log('Login error:', error.message);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    console.log('Login successful, setting cookie');
    
    // Enhanced cookie settings for cross-site authentication
    res.cookie('token', data.session.access_token, {
      httpOnly: true,
      secure: true, // Always use secure for cross-site
      sameSite: 'none', // Required for cross-site cookies
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
      domain: undefined, // Let browser set domain
    });

    res.json({ message: 'Login successful', user: data.user });
  } catch (error) {
    console.error('Login error:', error.message);
    res.status(500).json({ error: 'Failed to log in' });
  }
});

app.post('/api/logout', authenticate, async (req, res) => {
  try {
    // Clear the cookie - no need for admin signOut
    res.clearCookie('token', {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      domain: undefined
    });
    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    console.error('Logout error:', error.message);
    res.status(500).json({ error: 'Failed to log out' });
  }
});

// Profile Picture Upload
app.post('/api/profile/picture', authenticate, async (req, res) => {
  console.log('Profile picture upload - Files:', req.files);

  if (!req.files || !req.files.profilePicture) {
    return res.status(400).json({ error: 'No file uploaded' });
  }

  const file = req.files.profilePicture;
  const allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
  if (!allowedTypes.includes(file.mimetype)) {
    return res.status(400).json({ error: 'Only JPG, PNG, and GIF images are allowed' });
  }

  try {
    const userId = req.user.id;
    const fileName = `${Date.now()}-${Math.round(Math.random() * 1e9)}${path.extname(file.name)}`;
    const filePath = `profile_pictures/${fileName}`;

    // Upload to Supabase Storage
    const { error: uploadError } = await req.supabase.storage
      .from('uploads')
      .upload(filePath, file.data, { contentType: file.mimetype });

    if (uploadError) throw uploadError;

    // Get public URL
    const { data: { publicUrl } } = req.supabase.storage
      .from('uploads')
      .getPublicUrl(filePath);

    // Delete old profile picture if exists
    const { data: user } = await req.supabase
      .from('users')
      .select('profile_picture')
      .eq('id', userId)
      .single();

    if (user?.profile_picture) {
      const oldFileName = user.profile_picture.split('/').pop();
      await deleteStorageFiles('uploads', [`profile_pictures/${oldFileName}`]);
    }

    // Update user profile picture
    const { error: updateError } = await req.supabase
      .from('users')
      .update({ profile_picture: publicUrl })
      .eq('id', userId);

    if (updateError) throw updateError;

    res.json({ message: 'Profile picture updated', profilePicture: publicUrl });
  } catch (error) {
    console.error('Error uploading profile picture:', error.message);
    res.status(500).json({ error: 'Failed to upload profile picture' });
  }
});

// Enhanced Profile Route with robust error handling and explicit foreign key joins
app.get('/api/profile', authenticate, async (req, res) => {
  try {
    console.log('Fetching profile for user:', req.user.id);

    const userId = req.user.id;
    const id = req.query.id || userId;

    console.log('Profile ID to fetch:', id);

    const { data: profileUser, error: userError } = await req.supabase
      .from('users')
      .select('id, username, first_name, last_name, email, profile_picture')
      .eq('id', id)
      .single();

    if (userError) {
      console.error('User fetch error:', userError.message, userError);
      return res.status(404).json({ error: 'User not found (db error)' });
    }
    if (!profileUser) {
      console.error('User fetch error: No user found for id', id);
      return res.status(404).json({ error: 'User not found' });
    }

    // Validate and fix profile picture
    profileUser.profile_picture = validateProfilePicture(profileUser.profile_picture);

    // If profile picture was invalid, update the database
    if (profileUser.profile_picture !== req.query.profile_picture) {
      await req.supabase
        .from('users')
        .update({ profile_picture: profileUser.profile_picture })
        .eq('id', id);
    }

    console.log('Profile user found:', profileUser.username);

    const { data: posts, error: postsError } = await req.supabase
      .from('posts')
      .select(`
        *,
        author:users!posts_author_id_fkey(id, username, profile_picture),
        images(id, filename, created_at),
        post_likes(id, user_id),
        comments(
          id,
          content,
          created_at,
          author:users!comments_author_id_fkey(id, username, profile_picture)
        )
      `)
      .eq('author_id', id)
      .order('created_at', { ascending: false });

    if (postsError) {
      console.error('Posts fetch error:', postsError.message, postsError);
      return res.status(500).json({ error: 'Failed to load posts' });
    }

    const formattedPosts = posts.map(post => ({
      ...post,
      likedByUser: (post.post_likes || []).some(like => like.user_id === userId),
      likes: post.likes || 0, // Ensure likes count is included
      images: (post.images || []).map(img => ({
        id: img.id,
        url: `${process.env.SUPABASE_URL}/storage/v1/object/public/uploads/post_images/${img.filename}`,
        uploadedAt: img.created_at,
      })),
      comments: (post.comments || []).map(comment => ({
        ...comment,
        author: comment.author || {},
      })),
      post_likes: undefined, // Remove the raw post_likes data
    }));

    let friends = [];
    let incomingRequests = [];
    try {
      // Friends (accepted)
      const { data: friendsData, error: friendsError } = await req.supabase
        .from('friends')
        .select(`
          *,
          friend:users!friends_friend_id_fkey(id, username, first_name, last_name, profile_picture)
        `)
        .eq('user_id', id)
        .eq('friended', true);
      if (friendsError) throw friendsError;
      friends = friendsData || [];
    } catch (err) {
      console.error('Friends fetch error:', err.message, err);
      friends = [];
    }
    try {
      // Incoming requests (pending)
      const { data: requestsData, error: requestsError } = await req.supabase
        .from('friends')
        .select(`
          *,
          user:users!friends_user_id_fkey(id, username, first_name, last_name, profile_picture)
        `)
        .eq('friend_id', userId)
        .eq('friended', false);
      if (requestsError) throw requestsError;
      incomingRequests = requestsData || [];
    } catch (err) {
      console.error('Incoming requests fetch error:', err.message, err);
      incomingRequests = [];
    }

    console.log('Sending profile response');

    res.json({
      viewer: req.user,
      profileUser,
      posts: formattedPosts,
      friends,
      incomingRequests,
    });
  } catch (error) {
    console.error('Error loading profile:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to load profile', details: error.message });
  }
});

// Post Routes
app.post('/api/content', authenticate, async (req, res) => {
  console.log('Creating post - Body:', req.body);
  console.log('Creating post - Files:', req.files);

  const { title, content } = req.body;
  if (!title || !content) {
    return res.status(400).json({ error: 'Title and content are required' });
  }

  try {
    // Create post
    const { data: post, error: postError } = await req.supabase
      .from('posts')
      .insert({ title, content, author_id: req.user.id })
      .select()
      .single();

    if (postError) throw postError;

    // Handle image upload if present
    if (req.files?.image) {
      const file = req.files.image;
      const allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
      if (!allowedTypes.includes(file.mimetype)) {
        return res.status(400).json({ error: 'Only JPG, PNG, and GIF images are allowed' });
      }

      const fileName = `${Date.now()}-${Math.round(Math.random() * 1e9)}${path.extname(file.name)}`;
      const filePath = `post_images/${fileName}`;

      const { error: uploadError } = await req.supabase.storage
        .from('uploads')
        .upload(filePath, file.data, { contentType: file.mimetype });

      if (uploadError) throw uploadError;

      const { data: { publicUrl } } = req.supabase.storage
        .from('uploads')
        .getPublicUrl(filePath);

      const { error: imageError } = await req.supabase.from('images').insert({
        filename: fileName,
        path: filePath,
        mimetype: file.mimetype,
        uploader_id: req.user.id,
        post_id: post.id,
      });

      if (imageError) throw imageError;
    }

    res.status(201).json(post);
  } catch (error) {
    console.error('Error creating post:', error.message);
    res.status(500).json({ error: 'Could not create post' });
  }
});

app.get('/api/content', authenticate, async (req, res) => {
  try {
    console.log('Fetching content for user:', req.user.id);

    const userId = req.user.id;

    const { data: posts, error } = await req.supabase
      .from('posts')
      .select(`
        *,
        author:users!posts_author_id_fkey(id, username, profile_picture),
        images(id, filename, created_at),
        post_likes(id, user_id),
        comments(
          id,
          content,
          created_at,
          author:users!comments_author_id_fkey(id, username, profile_picture)
        )
      `)
      .order('id', { ascending: false });

    if (error) throw error;

    console.log('Posts fetched:', posts?.length || 0);

    const formattedPosts = posts.map(post => ({
      ...post,
      likedByUser: (post.post_likes || []).some(like => like.user_id === userId),
      likes: post.likes || 0, // Ensure likes count is included
      images: (post.images || []).map(img => ({
        id: img.id,
        url: `${process.env.SUPABASE_URL}/storage/v1/object/public/uploads/post_images/${img.filename}`,
        uploadedAt: img.created_at,
      })),
      comments: (post.comments || []).map(comment => ({
        ...comment,
        author: comment.author || {},
      })),
      post_likes: undefined, // Remove the raw post_likes data
    }));

    console.log('Sending response with posts:', formattedPosts.length);
    res.json({ posts: formattedPosts, user: req.user });
  } catch (error) {
    console.error('Failed to fetch posts:', error.message);
    res.status(500).json({ error: 'Failed to fetch posts' });
  }
});

// Comment Routes
app.post('/api/comments', authenticate, async (req, res) => {
  const { postId, content } = req.body;
  if (!postId || !content) {
    return res.status(400).json({ error: 'Post ID and content are required' });
  }

  try {
    const { data: comment, error } = await req.supabase
      .from('comments')
      .insert({
        content,
        author_id: req.user.id,
        post_id: postId,
      })
      .select()
      .single();

    if (error) throw error;
    res.status(201).json(comment);
  } catch (error) {
    console.error('Error creating comment:', error.message);
    res.status(500).json({ error: 'Failed to create comment' });
  }
});

app.get('/api/comments/:postId', authenticate, async (req, res) => {
  const postId = req.params.postId;
  const userId = req.user.id;

  if (isNaN(postId)) return res.status(400).json({ error: 'Invalid post ID' });

  try {
    const { data: comments, error } = await req.supabase
      .from('comments')
      .select(`
        *,
        author:users!comments_author_id_fkey(id, username, profile_picture),
        comment_likes(id, user_id)
      `)
      .eq('post_id', postId)
      .order('created_at', { ascending: true });

    if (error) throw error;

    const formattedComments = comments.map(comment => ({
      ...comment,
      likedByUser: (comment.comment_likes || []).some(like => like.user_id === userId),
      comment_likes: undefined,
    }));

    res.json(formattedComments);
  } catch (error) {
    console.error('Error fetching comments:', error.message);
    res.status(500).json({ error: 'Failed to fetch comments' });
  }
});

// Friend Routes
app.post('/api/profile/:id', authenticate, async (req, res) => {
  try {
    const friendId = req.params.id;
    const userId = req.user.id;

    if (userId === friendId) {
      return res.status(400).json({ error: 'You cannot add yourself' });
    }

    // Check for existing friend request or friendship in either direction
    const { data: existing, error: existingError } = await req.supabase
      .from('friends')
      .select('id, friended')
      .or(`and(user_id.eq.${userId},friend_id.eq.${friendId}),and(user_id.eq.${friendId},friend_id.eq.${userId})`);

    if (existingError) {
      console.error('Error checking for existing friend request:', existingError.message);
      return res.status(500).json({ error: 'Database error' });
    }

    if (existing && existing.length > 0) {
      return res.status(400).json({ error: 'Friend request or friendship already exists' });
    }

    const { data: newFriend, error: createError } = await req.supabase
      .from('friends')
      .insert({ user_id: userId, friend_id: friendId, friended: false })
      .select(`
        *,
        friend:users!friends_friend_id_fkey(id, username, first_name, last_name, profile_picture)
      `)
      .single();

    if (createError) {
      if (createError.code === '23505') {
        // Unique constraint violation
        return res.status(400).json({ error: 'Friend request or friendship already exists' });
      }
      console.error('Error creating friend request:', createError.message);
      return res.status(500).json({ error: 'Cannot add friend' });
    }

    res.status(201).json({ message: 'Friend request sent', data: newFriend });
  } catch (error) {
    console.error('Error adding friend:', error.message, error.stack);
    res.status(500).json({ error: 'Cannot add friend' });
  }
});

// Like Routes
app.post('/api/content/:id/like', authenticate, async (req, res) => {
  const postId = req.params.id;
  const userId = req.user.id;

  if (!postId) return res.status(400).json({ error: 'Invalid post ID' });

  try {
    const { data: existingLike, error: fetchError } = await req.supabase
      .from('post_likes')
      .select('id')
      .eq('user_id', userId)
      .eq('post_id', postId)
      .single();

    if (fetchError && fetchError.code !== 'PGRST116') throw fetchError;

    if (existingLike) {
      // Unlike
      await Promise.all([
        req.supabase.from('post_likes').delete().eq('id', existingLike.id),
        req.supabase.rpc('decrement_post_likes', { post_id: postId }),
      ]);
      return res.json({ liked: false });
    } else {
      // Like
      await Promise.all([
        req.supabase.from('post_likes').insert({ user_id: userId, post_id: postId }),
        req.supabase.rpc('increment_post_likes', { post_id: postId }),
      ]);
      return res.json({ liked: true });
    }
  } catch (error) {
    console.error('Error toggling post like:', error.message);
    res.status(500).json({ error: 'Failed to toggle post like' });
  }
});

app.post('/api/comments/:id/like', authenticate, async (req, res) => {
  const commentId = req.params.id;
  const userId = req.user.id;

  if (isNaN(commentId)) return res.status(400).json({ error: 'Invalid comment ID' });

  try {
    const { data: existingLike, error: fetchError } = await req.supabase
      .from('comment_likes')
      .select('id')
      .eq('user_id', userId)
      .eq('comment_id', commentId)
      .single();

    if (fetchError && fetchError.code !== 'PGRST116') throw fetchError;

    if (existingLike) {
      // Unlike
      await req.supabase.from('comment_likes').delete().eq('id', existingLike.id);
      return res.json({ liked: false });
    } else {
      // Like
      await req.supabase.from('comment_likes').insert({ user_id: userId, comment_id: commentId });
      return res.json({ liked: true });
    }
  } catch (error) {
    console.error('Error toggling comment like:', error.message);
    res.status(500).json({ error: 'Failed to toggle comment like' });
  }
});

// Message Routes
app.get('/api/message/:id', authenticate, async (req, res) => {
  const userId = req.user.id;
  const friendId = req.params.id;

  try {
    console.log('Message retrieval: userId', userId, 'friendId', friendId);
    const { data: friendExists, error: userError } = await req.supabase
      .from('users')
      .select('id')
      .eq('id', friendId)
      .single();

    if (userError || !friendExists) {
      console.error('User not found for messaging:', friendId, userError?.message);
      return res.status(404).json({ error: 'User not found' });
    }

    // Check if they are friends
    const { data: friendship, error: friendError } = await req.supabase
      .from('friends')
      .select('id')
      .or(`and(user_id.eq.${userId},friend_id.eq.${friendId},friended.eq.true),and(user_id.eq.${friendId},friend_id.eq.${userId},friended.eq.true)`)
      .single();

    if (friendError || !friendship) {
      console.error('Friendship check failed:', friendError?.message);
      return res.status(403).json({ error: 'You can only message your friends' });
    }

    const { data: messages, error } = await req.supabase
      .from('messages')
      .select(`
        *,
        sender:users!messages_sender_id_fkey(id, username, first_name, last_name, profile_picture),
        receiver:users!messages_receiver_id_fkey(id, username, first_name, last_name, profile_picture)
      `)
      .or(`and(sender_id.eq.${userId},receiver_id.eq.${friendId}),and(sender_id.eq.${friendId},receiver_id.eq.${userId})`)
      .order('created_at', { ascending: true });

    if (error) {
      console.error('Error retrieving messages:', error.message, error.stack);
      throw error;
    }

    console.log('Messages retrieved:', messages.length);
    const formattedMessages = messages.map(msg => ({
      ...msg,
      isSender: msg.sender_id === userId,
      senderName: `${msg.sender.first_name} ${msg.sender.last_name} (@${msg.sender.username})`,
    }));

    res.json({ messages: formattedMessages });
  } catch (error) {
    console.error('Error retrieving messages:', error.message, error.stack);
    res.status(500).json({ error: 'Cannot retrieve messages' });
  }
});

app.post('/api/message/:id', authenticate, async (req, res) => {
  const senderId = req.user.id;
  const receiverId = req.params.id;
  const { content } = req.body;

  if (!content) return res.status(400).json({ error: 'Message content is required' });

  try {
    const { data: receiver, error: userError } = await req.supabase
      .from('users')
      .select('id')
      .eq('id', receiverId)
      .single();

    if (userError || !receiver) return res.status(404).json({ error: 'Receiver not found' });

    const { data: message, error } = await req.supabase
      .from('messages')
      .insert({
        sender_id: senderId,
        receiver_id: receiverId,
        content,
      })
      .select(`
        *,
        sender:users!messages_sender_id_fkey(id, username, first_name, last_name, profile_picture),
        receiver:users!messages_receiver_id_fkey(id, username, first_name, last_name, profile_picture)
      `)
      .single();

    if (error) throw error;

    res.json({
      message: {
        ...message,
        isSender: true,
        senderName: `${message.sender.first_name} ${message.sender.last_name} (@${message.sender.username})`,
      },
    });
  } catch (error) {
    console.error('Error sending message:', error.message);
    res.status(500).json({ error: 'Cannot send message' });
  }
});

// User Routes
app.get('/api/users', authenticate, async (req, res) => {
  try {
    const { data: users, error } = await req.supabase
      .from('users')
      .select('id, username, first_name, last_name, profile_picture');
    if (error) throw error;
    res.json({ users });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Post Comment Routes
app.post('/api/content/:id/comment', authenticate, async (req, res) => {
  const postId = req.params.id;
  const { content } = req.body;
  if (!content) return res.status(400).json({ error: 'Content required' });
  try {
    const { data: comment, error } = await req.supabase
      .from('comments')
      .insert({ post_id: postId, author_id: req.user.id, content })
      .select(`
        *,
        author:users(id, username, profile_picture)
      `)
      .single();
    if (error) throw error;
    res.status(201).json(comment);
  } catch (error) {
    res.status(500).json({ error: 'Failed to add comment' });
  }
});

// Comment like endpoint (frontend expects /api/content/:id/comment/:commentId/like)
app.post('/api/content/:postId/comment/:commentId/like', authenticate, async (req, res) => {
  const commentId = req.params.commentId;
  const userId = req.user.id;

  if (isNaN(commentId)) return res.status(400).json({ error: 'Invalid comment ID' });

  try {
    const { data: existingLike, error: fetchError } = await req.supabase
      .from('comment_likes')
      .select('id')
      .eq('user_id', userId)
      .eq('comment_id', commentId)
      .single();

    if (fetchError && fetchError.code !== 'PGRST116') throw fetchError;

    if (existingLike) {
      // Unlike
      await req.supabase.from('comment_likes').delete().eq('id', existingLike.id);
      return res.json({ liked: false });
    } else {
      // Like
      await req.supabase.from('comment_likes').insert({ user_id: userId, comment_id: commentId });
      return res.json({ liked: true });
    }
  } catch (error) {
    console.error('Error toggling comment like:', error.message);
    res.status(500).json({ error: 'Failed to toggle comment like' });
  }
});

// Comment deletion endpoint (frontend expects /api/content/:id/comment/:commentId)
app.delete('/api/content/:postId/comment/:commentId', authenticate, async (req, res) => {
  const commentId = req.params.commentId;
  const userId = req.user.id;

  if (isNaN(commentId)) return res.status(400).json({ error: 'Invalid comment ID' });

  try {
    // Check if the comment exists and belongs to the user
    const { data: comment, error: fetchError } = await req.supabase
      .from('comments')
      .select('id, author_id')
      .eq('id', commentId)
      .single();

    if (fetchError || !comment) {
      return res.status(404).json({ error: 'Comment not found' });
    }

    if (comment.author_id !== userId) {
      return res.status(403).json({ error: 'You can only delete your own comments' });
    }

    // Delete the comment
    const { error: deleteError } = await req.supabase
      .from('comments')
      .delete()
      .eq('id', commentId)
      .eq('author_id', userId);

    if (deleteError) throw deleteError;

    res.json({ message: 'Comment deleted' });
  } catch (error) {
    console.error('Error deleting comment:', error.message);
    res.status(500).json({ error: 'Failed to delete comment' });
  }
});

// Delete Post Routes
app.delete('/api/content/:id', authenticate, async (req, res) => {
  const postId = req.params.id;
  try {
    const { error } = await req.supabase
      .from('posts')
      .delete()
      .eq('id', postId)
      .eq('author_id', req.user.id);
    if (error) throw error;
    res.json({ message: 'Post deleted' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete post' });
  }
});

// Update Post Routes
app.put('/api/content/:id', authenticate, async (req, res) => {
  const postId = req.params.id;
  const { title, content } = req.body;
  
  if (!title || !content) {
    return res.status(400).json({ error: 'Title and content are required' });
  }

  try {
    // First check if the post exists and belongs to the user
    const { data: existingPost, error: fetchError } = await req.supabase
      .from('posts')
      .select('id, author_id')
      .eq('id', postId)
      .single();

    if (fetchError || !existingPost) {
      return res.status(404).json({ error: 'Post not found' });
    }

    if (existingPost.author_id !== req.user.id) {
      return res.status(403).json({ error: 'You can only edit your own posts' });
    }

    // Update the post
    const { data: updatedPost, error: updateError } = await req.supabase
      .from('posts')
      .update({ title, content, updated_at: new Date().toISOString() })
      .eq('id', postId)
      .eq('author_id', req.user.id)
      .select()
      .single();

    if (updateError) throw updateError;

    res.json(updatedPost);
  } catch (error) {
    console.error('Error updating post:', error.message);
    res.status(500).json({ error: 'Failed to update post' });
  }
});

// Accept Friend Request
app.post('/api/profile/accept/:id', authenticate, async (req, res) => {
  const requestId = req.params.id;
  const userId = req.user.id;
  
  try {
    // First, verify this is a valid incoming friend request for the current user
    const { data: friendRequest, error: fetchError } = await req.supabase
      .from('friends')
      .select('*')
      .eq('id', requestId)
      .eq('friend_id', userId) // Current user is the one receiving the request
      .eq('friended', false)   // Request is pending
      .single();

    if (fetchError || !friendRequest) {
      return res.status(404).json({ error: 'Friend request not found or already processed' });
    }

    // Update the friend request to accepted
    const { error: updateError } = await req.supabase
      .from('friends')
      .update({ friended: true })
      .eq('id', requestId);

    if (updateError) throw updateError;

    // Create the reverse friendship (so both users are friends)
    const { error: insertError } = await req.supabase
      .from('friends')
      .insert({
        user_id: userId,
        friend_id: friendRequest.user_id,
        friended: true
      });

    if (insertError && insertError.code !== '23505') { // Ignore duplicate key errors
      throw insertError;
    }

    res.json({ message: 'Friend request accepted' });
  } catch (error) {
    console.error('Accept friend request error:', error.message);
    res.status(500).json({ error: 'Failed to accept friend request' });
  }
});

// Deny (delete) a friend request
app.delete('/api/profile/deny/:id', authenticate, async (req, res) => {
  const requestId = req.params.id;
  const userId = req.user.id;

  try {
    // Only allow the recipient to deny the request
    const { data: friendRequest, error: fetchError } = await req.supabase
      .from('friends')
      .select('*')
      .eq('id', requestId)
      .eq('friend_id', userId)
      .eq('friended', false)
      .single();

    if (fetchError || !friendRequest) {
      return res.status(404).json({ error: 'Friend request not found or already processed' });
    }

    // Delete the friend request
    const { error: deleteError } = await req.supabase
      .from('friends')
      .delete()
      .eq('id', requestId);

    if (deleteError) throw deleteError;

    res.json({ message: 'Friend request denied' });
  } catch (error) {
    console.error('Deny friend request error:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to deny friend request' });
  }
});

// Error Handling Middleware
app.use((err, req, res, next) => {
  console.error('Unexpected error:', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

// Start Server
const PORT = process.env.PORT || 5000;
app.get('/', (req, res) => {
  res.send('Backend is running. Use /api/* routes.');
});

const server = app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));

// Graceful Shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received. Closing server...');
  server.close(() => {
    console.log('Server closed.');
    process.exit(0);
  });
});
