import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import api from '../services/api';
import { useAuth } from '../context/AuthContext';

const Dashboard = () => {
  const { user, canCreatePosts } = useAuth();
  const [posts, setPosts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      const postsRes = await api.get('/posts/my');
      setPosts(postsRes.data.posts);
    } catch (err) {
      setError('Failed to load data');
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (postId) => {
    if (!window.confirm('Are you sure you want to delete this post?')) return;

    try {
      await api.delete(`/posts/${postId}`);
      setPosts(posts.filter(p => p._id !== postId));
    } catch (err) {
      setError('Failed to delete post');
    }
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: 'numeric',
      minute: '2-digit'
    });
  };

  if (loading) {
    return (
      <div className="content text-center">
        <div className="spinner" style={{ 
          borderTopColor: '#667eea',
          width: '40px',
          height: '40px',
          margin: '2rem auto'
        }}></div>
      </div>
    );
  }

  return (
    <div className="content">
      <h1>Welcome back, {user?.username}!</h1>
      <p className="mb-2">Manage your blog posts and account settings.</p>

      {error && <div className="alert alert-error">{error}</div>}

      {canCreatePosts && (
        <div className="mb-3">
          <Link to="/create-post" className="btn" style={{ fontSize: '1.1rem', padding: '1rem 2.5rem' }}>
            <span style={{ marginRight: '0.5rem' }}>+</span>
            Create New Post
          </Link>
        </div>
      )}

      <div className="mb-3">
        <h3 style={{ color: '#2d3748', borderBottom: '2px solid #e2e8f0', paddingBottom: '0.5rem' }}>
          Security Settings
        </h3>
        <div className="security-panel" style={{ marginTop: '1rem' }}>
          <div className="security-status">
            <div className="status-icon enabled">✓</div>
            <div>
              <strong style={{ color: '#065f46', fontSize: '1.1rem' }}>
                Local captcha protection enabled
              </strong>
              <p style={{ color: '#059669', fontSize: '0.95rem', margin: '0.5rem 0 0 0' }}>
                Login and registration now require a local captcha challenge.
              </p>
            </div>
          </div>
        </div>
      </div>

      <h3>Your Posts</h3>
      {posts.length === 0 ? (
        <div className="text-center\" style={{ 
          background: 'linear-gradient(135deg, #fef5e7 0%, #fde68a 50%, #fef5e7 100%)',
          borderRadius: '16px',
          padding: '3rem 2rem',
          margin: '2rem 0',
          border: '1px solid rgba(245, 158, 11, 0.2)'
        }}>
          <div style={{ fontSize: '3rem', marginBottom: '1rem' }}>📝</div>
          <h4 style={{ color: '#92400e', marginBottom: '1rem' }}>No posts yet!</h4>
          <p style={{ color: '#d97706', marginBottom: '2rem' }}>Start sharing your thoughts with the world.</p>
          {canCreatePosts && <Link to="/create-post" className="btn">Create Your First Post</Link>}
        </div>
      ) : (
        posts.map((post) => (
          <div key={post._id} className="post-card">
            <h4 style={{ 
              background: 'linear-gradient(135deg, #1a202c 0%, #2d3748 100%)',
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent',
              backgroundClip: 'text'
            }}>
              {post.title}
            </h4>
            <div className="post-meta">
              <span>Created: {formatDate(post.createdAt)}</span>
              {post.updatedAt && <span>Updated: {formatDate(post.updatedAt)}</span>}
            </div>
            <div className="post-actions">
              <Link to={`/post/${post.slug}`} className="btn btn-secondary">View</Link>
              <Link to={`/edit-post/${post._id}`} className="btn btn-secondary">Edit</Link>
              <button 
                onClick={() => handleDelete(post._id)} 
                className="btn btn-danger"
              >
                Delete
              </button>
            </div>
          </div>
        ))
      )}
    </div>
  );
};

export default Dashboard;
