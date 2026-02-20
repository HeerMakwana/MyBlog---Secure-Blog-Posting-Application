import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import api from '../services/api';
import { useAuth } from '../context/AuthContext';

const ViewPost = () => {
  const { slug } = useParams();
  const { user } = useAuth();
  const [post, setPost] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    fetchPost();
  }, [slug]);

  const fetchPost = async () => {
    try {
      const response = await api.get(`/posts/${slug}`);
      setPost(response.data.post);
    } catch (err) {
      setError(err.response?.status === 404 ? 'Post not found' : 'Failed to load post');
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

  if (error) {
    return (
      <div className="content">
        <div className="alert alert-error">{error}</div>
        <Link to="/" className="btn btn-secondary">← Back to Home</Link>
      </div>
    );
  }

  return (
    <div className="content">
      <article>
        <h1>{post.title}</h1>
        <div className="post-meta mb-2">
          <p>
            By <strong>{post.user?.username}</strong> on {formatDate(post.createdAt)}
          </p>
          {post.updatedAt && (
            <p>Last updated: {formatDate(post.updatedAt)}</p>
          )}
        </div>

        {post.imagePath && (
          <img 
            src={process.env.REACT_APP_API_URL ? `${process.env.REACT_APP_API_URL}${post.imagePath}` : post.imagePath} 
            alt="Post" 
            className="post-image" 
          />
        )}

        <div style={{ 
          color: '#4a5568', 
          lineHeight: '1.8', 
          fontSize: '1.1rem', 
          marginBottom: '2rem',
          whiteSpace: 'pre-wrap'
        }}>
          {post.body}
        </div>
      </article>

      <div className="mt-2" style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
        <Link to="/" className="btn btn-secondary">← Back to Home</Link>
        {user && user.id === post.user?._id && (
          <Link to={`/edit-post/${post._id}`} className="btn btn-secondary">Edit Post</Link>
        )}
      </div>
    </div>
  );
};

export default ViewPost;
