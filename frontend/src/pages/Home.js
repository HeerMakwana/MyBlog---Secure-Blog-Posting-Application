import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import api from '../services/api';
import { useAuth } from '../context/AuthContext';

const Home = () => {
  const [posts, setPosts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const { isAuthenticated, canCreatePosts } = useAuth();

  useEffect(() => {
    fetchPosts();
  }, []);

  const fetchPosts = async () => {
    try {
      const response = await api.get('/posts');
      setPosts(response.data.posts);
    } catch (err) {
      setError('Failed to load posts');
    } finally {
      setLoading(false);
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
      <h1>Welcome to MyBlog</h1>
      <p className="mb-3" style={{ fontSize: '1.2rem', color: '#4a5568' }}>
        A secure and user-friendly blogging platform with advanced security features.
      </p>

      {error && <div className="alert alert-error">{error}</div>}

      {posts.length === 0 ? (
        <div className="text-center" style={{ 
          padding: '3rem 2rem', 
          background: 'linear-gradient(135deg, #f8fafc 0%, #e2e8f0 100%)', 
          borderRadius: '16px',
          margin: '2rem 0'
        }}>
          <h3 style={{ color: '#4a5568', marginBottom: '1rem' }}>Welcome to MyBlog!</h3>
          <p style={{ color: '#718096', fontSize: '1.1rem', marginBottom: '2rem' }}>
            A secure and beautiful blogging platform awaits you.
          </p>
          {!isAuthenticated ? (
            <div style={{ display: 'flex', gap: '1rem', justifyContent: 'center', flexWrap: 'wrap' }}>
              <Link to="/register" className="btn">Get Started</Link>
              <Link to="/login" className="btn btn-secondary">Sign In</Link>
            </div>
          ) : canCreatePosts ? (
            <Link to="/create-post" className="btn">Create Your First Post</Link>
          ) : (
            <p style={{ color: '#718096' }}>Check back soon for new posts!</p>
          )}
        </div>
      ) : (
        posts.map((post) => (
          <article key={post._id} className="post-card">
            <h3>
              <Link to={`/post/${post.slug}`}>{post.title}</Link>
            </h3>
            <div className="post-meta">
              <span>By <strong>{post.user?.username}</strong></span>
              <span>on {formatDate(post.createdAt)}</span>
            </div>
            {post.imagePath && (
              <img 
                src={process.env.REACT_APP_API_URL ? `${process.env.REACT_APP_API_URL}${post.imagePath}` : post.imagePath} 
                alt="Post" 
                className="post-image" 
              />
            )}
            <div style={{ color: '#4a5568', lineHeight: '1.7', marginBottom: '1.5rem' }}>
              {post.body.substring(0, 250)}
              {post.body.length > 250 && '...'}
            </div>
            <div className="post-actions">
              <Link to={`/post/${post.slug}`} className="btn btn-secondary">Read Full Post</Link>
            </div>
          </article>
        ))
      )}
    </div>
  );
};

export default Home;
