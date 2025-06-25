require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const fileUpload = require('express-fileupload');
const path = require('path');
const { createClient } = require('@supabase/supabase-js');

// Environment variable validation
const requiredEnvVars = ['SUPABASE_URL', 'SUPABASE_KEY', 'CLIENT_URL'];
for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    console.error(`Missing required environment variable: ${envVar}`);
    process.exit(1);
  }
}

const app = express();
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

// Middleware
app.use(cors({
  origin: 'https://social-media-frontend-ezqu.vercel.app', // Preserved as requested
  credentials: true,
}));

app.use(bodyParser.json());
app.use(cookieParser());
app.use(fileUpload({
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  abortOnLimit: true, // Abort upload if limit exceeded
}));
app.disable('x-powered-by');

// Utility function to delete files from Supabase Storage
const deleteStorageFiles = async (bucket, paths) => {
  if (paths.length === 0) return;
  const { error } = await supabase.storage.from(bucket).remove(paths);
  if (error) throw error;
};

// Middleware to verify Supabase JWT
const authenticate = async (req, res, next) => {
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
  next();
};

// Auth Routes
app.post('/api/signup', async (req, res) => {
  const { username, password, firstName, lastName, email } = req.body;
  if (!username || !password || !firstName || !lastName || !email) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  try {
    // Check for existing username or email
    const { data: existingUser } = await supabase
      .from('users')
      .select('id')
      .or(`username.eq.${username},email.eq.${email}`)
      .single();

    if (existingUser) {
      return res.status(400).json({ error: 'Username or email already in use' });
    }

    // Sign up user with Supabase Auth
    const { data: authUser, error: authError } = await supabase.auth.signUp({
      email,
      password,
      options: {
        data: { username, firstName, lastName },
      },
    });

    if (authError) throw authError;

    // Insert user into users table
    const { error: dbError } = await supabase
      .from('users')
      .insert({
        id: authUser.user.id,
        username,
        first_name: firstName,
        last_name: lastName,
        email,
      });

    if (dbError) throw dbError;

    res.status(201).json({ message: 'User created successfully' });
  } catch (error) {
    console.error('Signup error:', error.message);
    res.status(500).json({ error: 'Failed to sign up' });
  }
});

app.options('/api/login', cors());

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
    res.cookie('token', data.session.access_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      maxAge: 24 * 60 * 60 * 1000,
    });

    res.json({ message: 'Login successful', user: data.user });
  } catch (error) {
    console.error('Login error:', error.message);
    res.status(500).json({ error: 'Failed to log in' });
  }
});
app.post('/api/logout', authenticate, async (req, res) => {
  try {
    const token = req.cookies.token;
    const { error } = await supabase.auth.admin.signOut(token);
    if (error) throw error;

    res.clearCookie('token');
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
    const { error: uploadError } = await supabase.storage
      .from('uploads')
      .upload(filePath, file.data, { contentType: file.mimetype });

    if (uploadError) throw uploadError;

    // Get public URL
    const { data: { publicUrl } } = supabase.storage
      .from('uploads')
      .getPublicUrl(filePath);

    // Delete old profile picture if exists
    const { data: user } = await supabase
      .from('users')
      .select('profile_picture')
      .eq('id', userId)
      .single();

    if (user?.profile_picture) {
      const oldFileName = user.profile_picture.split('/').pop();
      await deleteStorageFiles('uploads', [`profile_pictures/${oldFileName}`]);
    }

    // Update user profile picture
    const { error: updateError } = await supabase
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

// Delete Profile
app.delete('/api/profile', authenticate, async (req, res) => {
  const userId = req.user.id;

  try {
    // Delete images from Supabase Storage
    const { data: images } = await supabase
      .from('images')
      .select('path')
      .eq('uploader_id', userId);

    if (images?.length > 0) {
      const paths = images.map(img => img.path.split('/').slice(-2).join('/'));
      await deleteStorageFiles('uploads', paths);
    }

    // Delete profile picture from Supabase Storage
    const { data: user } = await supabase
      .from('users')
      .select('profile_picture')
      .eq('id', userId)
      .single();

    if (user?.profile_picture) {
      const fileName = user.profile_picture.split('/').pop();
      await deleteStorageFiles('uploads', [`profile_pictures/${fileName}`]);
    }

    // Delete related data
    await Promise.all([
      supabase.from('images').delete().eq('uploader_id', userId),
      supabase.from('comments').delete().eq('author_id', userId),
      supabase.from('posts').delete().eq('author_id', userId),
      supabase.from('messages').delete().or(`sender_id.eq.${userId},receiver_id.eq.${userId}`),
      supabase.from('friends').delete().or(`user_id.eq.${userId},friend_id.eq.${userId}`),
      supabase.from('users').delete().eq('id', userId),
    ]);

    // Sign out and clear cookie
    const { error } = await supabase.auth.admin.signOut(req.cookies.token);
    if (error) console.error('Sign out error:', error.message);

    res.clearCookie('token');
    res.json({ message: 'Profile deleted successfully' });
  } catch (error) {
    console.error('Error deleting profile:', error.message);
    res.status(500).json({ error: 'Failed to delete profile' });
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
    const { data: post, error: postError } = await supabase
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

      const { error: uploadError } = await supabase.storage
        .from('uploads')
        .upload(filePath, file.data, { contentType: file.mimetype });

      if (uploadError) throw uploadError;

      const { data: { publicUrl } } = supabase.storage
        .from('uploads')
        .getPublicUrl(filePath);

      const { error: imageError } = await supabase.from('images').insert({
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

    const { data: posts, error } = await supabase
      .from('posts')
      .select(`
        *,
        author:users(username, id, profile_picture),
        images(id, filename, created_at),
        post_likes(id, user_id)
      `)
      .order('id', { ascending: false });

    if (error) throw error;

    console.log('Posts fetched:', posts?.length || 0);

    const formattedPosts = posts.map(post => ({
      ...post,
      likedByUser: post.post_likes.some(like => like.user_id === userId),
      images: post.images.map(img => ({
        id: img.id,
        url: `${process.env.SUPABASE_URL}/storage/v1/object/public/uploads/post_images/${img.filename}`,
        uploadedAt: img.created_at,
      })),
      post_likes: undefined,
    }));

    console.log('Sending response with posts:', formattedPosts.length);
    res.json({ posts: formattedPosts, user: req.user });
  } catch (error) {
    console.error('Failed to fetch posts:', error.message);
    res.status(500).json({ error: 'Failed to fetch posts' });
  }
});

app.get('/api/content/:id', authenticate, async (req, res) => {
  const postId = parseInt(req.params.id);
  if (isNaN(postId)) return res.status(400).json({ error: 'Invalid post ID' });

  try {
    const { data: post, error } = await supabase
      .from('posts')
      .select(`
        *,
        author:users(id, username, profile_picture),
        images(id, filename, created_at)
      `)
      .eq('id', postId)
      .single();

    if (error || !post) return res.status(404).json({ error: 'Post not found' });
    if (post.author_id !== req.user.id) return res.status(403).json({ error: 'Unauthorized' });

    const imageUrls = post.images.map(img => ({
      id: img.id,
      url: `${process.env.SUPABASE_URL}/storage/v1/object/public/uploads/post_images/${img.filename}`,
      uploadedAt: img.created_at,
    }));

    res.json({ post: { ...post, images: imageUrls } });
  } catch (error) {
    console.error('Error fetching post:', error.message);
    res.status(500).json({ error: 'Failed to fetch post' });
  }
});

app.put('/api/content/:id', authenticate, async (req, res) => {
  const postId = parseInt(req.params.id);
  const { title, content } = req.body;
  if (isNaN(postId)) return res.status(400).json({ error: 'Invalid post ID' });
  if (!title || !content) return res.status(400).json({ error: 'Title and content are required' });

  try {
    const { data: post, error: fetchError } = await supabase
      .from('posts')
      .select('author_id')
      .eq('id', postId)
      .single();

    if (fetchError || !post) return res.status(404).json({ error: 'Post not found' });
    if (post.author_id !== req.user.id) return res.status(403).json({ error: 'Unauthorized' });

    const { data: updated, error: updateError } = await supabase
      .from('posts')
      .update({ title, content, updated_at: new Date() })
      .eq('id', postId)
      .select()
      .single();

    if (updateError) throw updateError;
    res.json(updated);
  } catch (error) {
    console.error('Error updating post:', error.message);
    res.status(500).json({ error: 'Failed to update post' });
  }
});

app.delete('/api/content/:id', authenticate, async (req, res) => {
  const postId = parseInt(req.params.id);
  if (isNaN(postId)) return res.status(400).json({ error: 'Invalid post ID' });

  try {
    const { data: post, error: fetchError } = await supabase
      .from('posts')
      .select('author_id')
      .eq('id', postId)
      .single();

    if (fetchError || !post) return res.status(404).json({ error: 'Post not found' });
    if (post.author_id !== req.user.id) return res.status(403).json({ error: 'Unauthorized' });

    // Delete associated images
    const { data: images } = await supabase
      .from('images')
      .select('filename')
      .eq('post_id', postId);

    if (images?.length > 0) {
      const paths = images.map(img => `post_images/${img.filename}`);
      await deleteStorageFiles('uploads', paths);
    }

    await Promise.all([
      supabase.from('images').delete().eq('post_id', postId),
      supabase.from('posts').delete().eq('id', postId),
    ]);

    res.json({ message: 'Post deleted successfully' });
  } catch (error) {
    console.error('Error deleting post:', error.message);
    res.status(500).json({ error: 'Failed to delete post' });
  }
});

// Comment Routes
app.post('/api/comments', authenticate, async (req, res) => {
  const { content, postId } = req.body;
  if (!content || !postId) return res.status(400).json({ error: 'Content and postId are required' });

  try {
    const { data: post, error: postError } = await supabase
      .from('posts')
      .select('id')
      .eq('id', parseInt(postId))
      .single();

    if (postError || !post) return res.status(404).json({ error: 'Post not found' });

    const { data: comment, error: commentError } = await supabase
      .from('comments')
      .insert({
        content,
        post_id: parseInt(postId),
        author_id: req.user.id,
      })
      .select()
      .single();

    if (commentError) throw commentError;
    res.status(201).json(comment);
  } catch (error) {
    console.error('Error creating comment:', error.message);
    res.status(500).json({ error: 'Failed to create comment' });
  }
});

app.get('/api/comments/:postId', authenticate, async (req, res) => {
  const postId = parseInt(req.params.postId);
  const userId = req.user.id;

  if (isNaN(postId)) return res.status(400).json({ error: 'Invalid post ID' });

  try {
    const { data: comments, error } = await supabase
      .from('comments')
      .select(`
        *,
        author:users(username, id, profile_picture),
        comment_likes(id, user_id)
      `)
      .eq('post_id', postId)
      .order('created_at', { ascending: true });

    if (error) throw error;

    const formattedComments = comments.map(comment => ({
      ...comment,
      likedByUser: comment.comment_likes.some(like => like.user_id === userId),
      comment_likes: undefined,
    }));

    res.json(formattedComments);
  } catch (error) {
    console.error('Error fetching comments:', error.message);
    res.status(500).json({ error: 'Failed to fetch comments' });
  }
});

// Profile Route
app.get('/api/profile', authenticate, async (req, res) => {
  try {
    console.log('Fetching profile for user:', req.user.id);

    const userId = req.user.id;
    const id = req.query.id || userId;

    console.log('Profile ID to fetch:', id);

    const { data: profileUser, error: userError } = await supabase
      .from('users')
      .select('id, username, first_name, last_name, email, profile_picture')
      .eq('id', id)
      .single();

    if (userError || !profileUser) {
      console.error('User fetch error:', userError?.message);
      return res.status(404).json({ error: 'User not found' });
    }

    console.log('Profile user found:', profileUser.username);

    const { data: posts, error: postsError } = await supabase
      .from('posts')
      .select(`
        *,
        images(id, filename, created_at)
      `)
      .eq('author_id', id)
      .order('created_at', { ascending: false });

    if (postsError) throw postsError;

    console.log('Posts found:', posts?.length || 0);

    const formattedPosts = posts.map(post => ({
      ...post,
      images: post.images.map(img => ({
        id: img.id,
        url: `${process.env.SUPABASE_URL}/storage/v1/object/public/uploads/post_images/${img.filename}`,
        uploadedAt: img.created_at,
      })),
    }));

    const { data: friends, error: friendsError } = await supabase
      .from('friends')
      .select(`
        *,
        friend:users(id, username, first_name, last_name, profile_picture)
      `)
      .eq('user_id', id)
      .eq('friended', true);

    if (friendsError) throw friendsError;

    const { data: incomingRequests, error: requestsError } = await supabase
      .from('friends')
      .select(`
        *,
        user:users(id, username, first_name, last_name, profile_picture)
      `)
      .eq('friend_id', userId)
      .eq('friended', false);

    if (requestsError) throw requestsError;

    console.log('Sending profile response');

    res.json({
      viewer: req.user,
      profileUser,
      posts: formattedPosts,
      friends: friends || [],
      incomingRequests: incomingRequests || [],
    });
  } catch (error) {
    console.error('Error loading profile:', error.message);
    res.status(500).json({ error: 'Failed to load profile' });
  }
});

// Send Friend Request
app.post('/api/profile/:id', authenticate, async (req, res) => {
  try {
    const friendId = req.params.id;
    const userId = req.user.id;

    if (userId === friendId) {
      return res.status(400).json({ error: 'You cannot add yourself' });
    }

    const { data: friendExists, error: userError } = await supabase
      .from('users')
      .select('id')
      .eq('id', friendId)
      .single();

    if (userError || !friendExists) return res.status(404).json({ error: 'User not found' });

    const { data: existing, error: existingError } = await supabase
      .from('friends')
      .select('id')
      .or(`and(user_id.eq.${userId},friend_id.eq.${friendId}),and(user_id.eq.${friendId},friend_id.eq.${userId})`)
      .single();

    if (existing) {
      return res.status(400).json({ error: 'Friend request or friendship already exists' });
    }

    const { data: newFriend, error: createError } = await supabase
      .from('friends')
      .insert({ user_id: userId, friend_id: friendId, friended: false })
      .select(`
        *,
        friend:users(id, username, first_name, last_name, profile_picture)
      `)
      .single();

    if (createError) throw createError;

    res.status(201).json({ message: 'Friend request sent', data: newFriend });
  } catch (error) {
    console.error('Error adding friend:', error.message);
    res.status(500).json({ error: 'Cannot add friend' });
  }
});

// Toggle Post Like
app.post('/api/content/:id/like', authenticate, async (req, res) => {
  const postId = parseInt(req.params.id);
  const userId = req.user.id;

  if (isNaN(postId)) return res.status(400).json({ error: 'Invalid post ID' });

  try {
    const { data: existingLike, error: fetchError } = await supabase
      .from('post_likes')
      .select('id')
      .eq('user_id', userId)
      .eq('post_id', postId)
      .single();

    if (fetchError && fetchError.code !== 'PGRST116') throw fetchError;

    if (existingLike) {
      // Unlike
      await Promise.all([
        supabase.from('post_likes').delete().eq('id', existingLike.id),
        supabase.rpc('decrement_post_likes', { post_id: postId }),
      ]);
      return res.json({ liked: false });
    } else {
      // Like
      await Promise.all([
        supabase.from('post_likes').insert({ user_id: userId, post_id: postId }),
        supabase.rpc('increment_post_likes', { post_id: postId }),
      ]);
      return res.json({ liked: true });
    }
  } catch (error) {
    console.error('Error toggling post like:', error.message);
    res.status(500).json({ error: 'Failed to toggle post like' });
  }
});

// Toggle Comment Like
app.post('/api/comments/:id/like', authenticate, async (req, res) => {
  const commentId = parseInt(req.params.id);
  const userId = req.user.id;

  if (isNaN(commentId)) return res.status(400).json({ error: 'Invalid comment ID' });

  try {
    const { data: existingLike, error: fetchError } = await supabase
      .from('comment_likes')
      .select('id')
      .eq('user_id', userId)
      .eq('comment_id', commentId)
      .single();

    if (fetchError && fetchError.code !== 'PGRST116') throw fetchError;

    if (existingLike) {
      // Unlike
      await supabase.from('comment_likes').delete().eq('id', existingLike.id);
      return res.json({ liked: false });
    } else {
      // Like
      await supabase.from('comment_likes').insert({ user_id: userId, comment_id: commentId });
      return res.json({ liked: true });
    }
  } catch (error) {
    console.error('Error toggling comment like:', error.message);
    res.status(500).json({ error: 'Failed to toggle comment like' });
  }
});

// Accept Friend Request
app.post('/api/profile/accept/:requestId', authenticate, async (req, res) => {
  try {
    const requestId = parseInt(req.params.requestId);
    const userId = req.user.id;

    if (isNaN(requestId)) return res.status(400).json({ error: 'Invalid request ID' });

    const { data: friendRequest, error: fetchError } = await supabase
      .from('friends')
      .select('user_id, friend_id, friended')
      .eq('id', requestId)
      .single();

    if (fetchError || !friendRequest) {
      return res.status(404).json({ error: 'Friend request not found' });
    }

    if (friendRequest.friend_id !== userId) {
      return res.status(403).json({ error: 'Not authorized to accept this request' });
    }

    if (friendRequest.friended) {
      return res.status(400).json({ error: 'Request already accepted' });
    }

    await supabase
      .from('friends')
      .update({ friended: true })
      .eq('id', requestId);

    const { data: reciprocal } = await supabase
      .from('friends')
      .select('id')
      .eq('user_id', userId)
      .eq('friend_id', friendRequest.user_id)
      .single();

    if (!reciprocal) {
      await supabase
        .from('friends')
        .insert({
          user_id: userId,
          friend_id: friendRequest.user_id,
          friended: true,
        });
    }

    res.json({ message: 'Friend request accepted' });
  } catch (error) {
    console.error('Error accepting friend request:', error.message);
    res.status(500).json({ error: 'Cannot accept friend request' });
  }
});

// Unfriend Endpoint
app.delete('/api/profile/unfriend/:friendId', authenticate, async (req, res) => {
  try {
    const userId = req.user.id;
    const friendId = req.params.friendId;

    if (userId === friendId) {
      return res.status(400).json({ error: 'Cannot unfriend yourself' });
    }

    const { data: friendExists, error: userError } = await supabase
      .from('users')
      .select('id')
      .eq('id', friendId)
      .single();

    if (userError || !friendExists) return res.status(404).json({ error: 'User not found' });

    const { data: friendship, error: friendshipError } = await supabase
      .from('friends')
      .select('id')
      .or(`and(user_id.eq.${userId},friend_id.eq.${friendId},friended.eq.true),and(user_id.eq.${friendId},friend_id.eq.${userId},friended.eq.true)`)
      .single();

    if (friendshipError && friendshipError.code !== 'PGRST116') throw friendshipError;
    if (!friendship) {
      return res.status(400).json({ error: 'No friendship exists' });
    }

    await supabase
      .from('friends')
      .delete()
      .or(`and(user_id.eq.${userId},friend_id.eq.${friendId}),and(user_id.eq.${friendId},friend_id.eq.${userId})`);

    res.json({ message: 'Unfriended successfully' });
  } catch (error) {
    console.error('Error unfriending:', error.message);
    res.status(500).json({ error: 'Failed to unfriend' });
  }
});

// Message Routes
app.get('/api/message/:id', authenticate, async (req, res) => {
  const userId = req.user.id;
  const friendId = req.params.id;

  try {
    const { data: friendExists, error: userError } = await supabase
      .from('users')
      .select('id')
      .eq('id', friendId)
      .single();

    if (userError || !friendExists) return res.status(404).json({ error: 'User not found' });

    const { data: messages, error } = await supabase
      .from('messages')
      .select(`
        *,
        sender:users(id, username, first_name, last_name, profile_picture),
        receiver:users(id, username, first_name, last_name, profile_picture)
      `)
      .or(`and(sender_id.eq.${userId},receiver_id.eq.${friendId}),and(sender_id.eq.${friendId},receiver_id.eq.${userId})`)
      .order('created_at', { ascending: true });

    if (error) throw error;

    const formattedMessages = messages.map(msg => ({
      ...msg,
      isSender: msg.sender_id === userId,
      senderName: `${msg.sender.first_name} ${msg.sender.last_name} (@${msg.sender.username})`,
    }));

    res.json({ messages: formattedMessages });
  } catch (error) {
    console.error('Error retrieving messages:', error.message);
    res.status(500).json({ error: 'Cannot retrieve messages' });
  }
});

app.post('/api/message/:id', authenticate, async (req, res) => {
  const senderId = req.user.id;
  const receiverId = req.params.id;
  const { content } = req.body;

  if (!content) return res.status(400).json({ error: 'Message content is required' });

  try {
    const { data: receiver, error: userError } = await supabase
      .from('users')
      .select('id')
      .eq('id', receiverId)
      .single();

    if (userError || !receiver) return res.status(404).json({ error: 'Receiver not found' });

    const { data: message, error } = await supabase
      .from('messages')
      .insert({
        sender_id: senderId,
        receiver_id: receiverId,
        content,
      })
      .select(`
        *,
        sender:users(id, username, first_name, last_name, profile_picture),
        receiver:users(id, username, first_name, last_name, profile_picture)
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

// Delete Profile by ID (Admin)
app.delete('/api/profile/:id', authenticate, async (req, res) => {
  try {
    const userId = req.user.id;
    const targetId = req.params.id;

    const { data: user, error: userError } = await supabase
      .from('users')
      .select('is_admin')
      .eq('id', userId)
      .single();

    if (userError || !user || !user.is_admin) {
      return res.status(403).json({ error: 'Unauthorized: Admin access required' });
    }

    const { data: targetUser, error: targetError } = await supabase
      .from('users')
      .select('id, profile_picture')
      .eq('id', targetId)
      .single();

    if (targetError || !targetUser) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Delete images from Supabase Storage
    const { data: images } = await supabase
      .from('images')
      .select('path')
      .eq('uploader_id', targetId);

    if (images?.length > 0) {
      const paths = images.map(img => img.path.split('/').slice(-2).join('/'));
      await deleteStorageFiles('uploads', paths);
    }

    // Delete profile picture
    if (targetUser.profile_picture) {
      const fileName = targetUser.profile_picture.split('/').pop();
      await deleteStorageFiles('uploads', [`profile_pictures/${fileName}`]);
    }

    // Delete related data
    await Promise.all([
      supabase.from('images').delete().eq('uploader_id', targetId),
      supabase.from('comments').delete().eq('author_id', targetId),
      supabase.from('posts').delete().eq('author_id', targetId),
      supabase.from('messages').delete().or(`sender_id.eq.${targetId},receiver_id.eq.${targetId}`),
      supabase.from('friends').delete().or(`user_id.eq.${targetId},friend_id.eq.${targetId}`),
      supabase.from('users').delete().eq('id', targetId),
    ]);

    res.json({ message: 'Profile deleted successfully' });
  } catch (error) {
    console.error('Error deleting profile:', error.message);
    res.status(500).json({ error: 'Failed to delete profile' });
  }
});

// Profile Picture Delete
app.delete('/api/profile/picture', authenticate, async (req, res) => {
  try {
    const userId = req.user.id;
    const { data: user, error: userError } = await supabase
      .from('users')
      .select('profile_picture')
      .eq('id', userId)
      .single();

    if (userError || !user) return res.status(404).json({ error: 'User not found' });
    if (!user.profile_picture) {
      return res.status(400).json({ error: 'No profile picture to delete' });
    }

    // Delete profile picture from Supabase Storage
    const fileName = user.profile_picture.split('/').pop();
    await deleteStorageFiles('uploads', [`profile_pictures/${fileName}`]);

    // Update user
    const { error: updateError } = await supabase
      .from('users')
      .update({ profile_picture: null })
      .eq('id', userId);

    if (updateError) throw updateError;

    res.json({ message: 'Profile picture deleted successfully' });
  } catch (error) {
    console.error('Error deleting profile picture:', error.message);
    res.status(500).json({ error: 'Failed to delete profile picture' });
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