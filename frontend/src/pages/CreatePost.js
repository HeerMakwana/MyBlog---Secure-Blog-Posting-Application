import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import api from '../services/api';

const CreatePost = () => {
  const [title, setTitle] = useState('');
  const [body, setBody] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    // Validation
    if (!title || !body) {
      setError('Title and body are required');
      setLoading(false);
      return;
    }

    if (title.length < 3 || title.length > 255) {
      setError('Title must be between 3 and 255 characters');
      setLoading(false);
      return;
    }

    if (body.length < 10) {
      setError('Body must be at least 10 characters');
      setLoading(false);
      return;
    }

    try {
      const response = await api.post('/posts', { title, body });
      navigate(`/post/${response.data.post.slug}`);
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to create post');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="content">
      <h1>Create New Post</h1>
      <p className="mb-2">Share your thoughts with the world.</p>

      {error && <div className="alert alert-error">{error}</div>}

      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label htmlFor="title">Post Title</label>
          <input
            type="text"
            id="title"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            required
          />
        </div>

        <div className="form-group">
          <label htmlFor="body">Post Content</label>
          <textarea
            id="body"
            value={body}
            onChange={(e) => setBody(e.target.value)}
            rows="12"
            required
            placeholder="Write your post content here..."
          />
        </div>

        <div className="mt-2" style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
          <button type="submit" className="btn" disabled={loading}>
            {loading ? <span className="spinner"></span> : 'Publish Post'}
          </button>
          <Link to="/dashboard" className="btn btn-secondary">Cancel</Link>
        </div>
      </form>
    </div>
  );
};

export default CreatePost;
