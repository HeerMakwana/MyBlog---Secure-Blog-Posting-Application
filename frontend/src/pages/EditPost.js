import React, { useState, useEffect } from 'react';
import { useNavigate, useParams, Link } from 'react-router-dom';
import api from '../services/api';

const EditPost = () => {
  const { id } = useParams();
  const [title, setTitle] = useState('');
  const [body, setBody] = useState('');
  const [slug, setSlug] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [fetching, setFetching] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    const fetchPost = async () => {
      try {
        // First get user's posts to find this one
        const response = await api.get('/posts/my');
        const post = response.data.posts.find(p => p._id === id);
        
        if (!post) {
          setError('Post not found or unauthorized');
          return;
        }

        setTitle(post.title);
        setBody(post.body);
        setSlug(post.slug);
      } catch (err) {
        setError('Failed to load post');
      } finally {
        setFetching(false);
      }
    };

    fetchPost();
  }, [id]);

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
      const response = await api.put(`/posts/${id}`, { title, body });
      navigate(`/post/${response.data.post.slug}`);
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to update post');
    } finally {
      setLoading(false);
    }
  };

  if (fetching) {
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
      <h1>Edit Post</h1>
      <p className="mb-2">Make changes to your post.</p>

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
            {loading ? <span className="spinner"></span> : 'Save Changes'}
          </button>
          <Link to={`/post/${slug}`} className="btn btn-secondary">View Post</Link>
          <Link to="/dashboard" className="btn btn-secondary">Cancel</Link>
        </div>
      </form>
    </div>
  );
};

export default EditPost;
