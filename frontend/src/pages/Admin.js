import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import api from '../services/api';

const Admin = () => {
  const [users, setUsers] = useState([]);
  const [posts, setPosts] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [tab, setTab] = useState('stats');

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      const [usersRes, postsRes, statsRes] = await Promise.all([
        api.get('/admin/users'),
        api.get('/admin/posts'),
        api.get('/admin/stats')
      ]);
      setUsers(usersRes.data.users);
      setPosts(postsRes.data.posts);
      setStats(statsRes.data.stats);
    } catch (err) {
      setError('Failed to load admin data');
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteUser = async (userId, username) => {
    if (!window.confirm(`Delete user ${username}? This will remove all their posts.`)) return;

    try {
      await api.delete(`/admin/users/${userId}`);
      setUsers(users.filter(u => u._id !== userId));
      setPosts(posts.filter(p => p.user?._id !== userId));
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to delete user');
    }
  };

  const handleDeletePost = async (postId) => {
    if (!window.confirm('Delete this post?')) return;

    try {
      await api.delete(`/admin/posts/${postId}`);
      setPosts(posts.filter(p => p._id !== postId));
    } catch (err) {
      setError('Failed to delete post');
    }
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric'
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
      <h1>Admin Panel</h1>
      
      {error && <div className="alert alert-error">{error}</div>}

      {/* Tab Navigation */}
      <div style={{ 
        display: 'flex', 
        gap: '0.5rem', 
        marginBottom: '2rem',
        borderBottom: '2px solid #e2e8f0',
        paddingBottom: '1rem'
      }}>
        <button 
          onClick={() => setTab('stats')}
          className={`btn ${tab === 'stats' ? '' : 'btn-secondary'}`}
        >
          Dashboard
        </button>
        <button 
          onClick={() => setTab('users')}
          className={`btn ${tab === 'users' ? '' : 'btn-secondary'}`}
        >
          Users ({users.length})
        </button>
        <button 
          onClick={() => setTab('posts')}
          className={`btn ${tab === 'posts' ? '' : 'btn-secondary'}`}
        >
          Posts ({posts.length})
        </button>
      </div>

      {/* Stats Tab */}
      {tab === 'stats' && stats && (
        <div>
          <div style={{ 
            display: 'grid', 
            gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
            gap: '1.5rem',
            marginBottom: '2rem'
          }}>
            <div style={{ 
              background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
              padding: '2rem',
              borderRadius: '16px',
              color: 'white'
            }}>
              <h3 style={{ fontSize: '2.5rem', marginBottom: '0.5rem' }}>{stats.totalUsers}</h3>
              <p>Total Users</p>
            </div>
            <div style={{ 
              background: 'linear-gradient(135deg, #48bb78 0%, #38a169 100%)',
              padding: '2rem',
              borderRadius: '16px',
              color: 'white'
            }}>
              <h3 style={{ fontSize: '2.5rem', marginBottom: '0.5rem' }}>{stats.totalPosts}</h3>
              <p>Total Posts</p>
            </div>
          </div>

          <h3>Recent Activity</h3>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '1.5rem' }}>
            <div>
              <h4 className="mb-2">Latest Users</h4>
              {stats.recentUsers.map(u => (
                <div key={u._id} style={{ 
                  padding: '0.75rem',
                  background: '#f8fafc',
                  borderRadius: '8px',
                  marginBottom: '0.5rem'
                }}>
                  <strong>{u.username}</strong>
                  <span style={{ color: '#718096', marginLeft: '0.5rem' }}>{u.email}</span>
                </div>
              ))}
            </div>
            <div>
              <h4 className="mb-2">Latest Posts</h4>
              {stats.recentPosts.map(p => (
                <div key={p._id} style={{ 
                  padding: '0.75rem',
                  background: '#f8fafc',
                  borderRadius: '8px',
                  marginBottom: '0.5rem'
                }}>
                  <strong>{p.title}</strong>
                  <span style={{ color: '#718096', marginLeft: '0.5rem' }}>by {p.user?.username}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Users Tab */}
      {tab === 'users' && (
        <section>
          <h3>Users</h3>
          <table className="admin-table">
            <thead>
              <tr>
                <th>Username</th>
                <th>Email</th>
                <th>Created</th>
                <th style={{ textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map(u => (
                <tr key={u._id}>
                  <td>{u.username} {u.isAdmin && <span style={{ color: '#667eea', fontWeight: 'bold' }}>(Admin)</span>}</td>
                  <td>{u.email}</td>
                  <td>{formatDate(u.createdAt)}</td>
                  <td style={{ textAlign: 'right' }}>
                    <button 
                      onClick={() => handleDeleteUser(u._id, u.username)}
                      className="btn btn-danger"
                      style={{ padding: '0.5rem 1rem', fontSize: '0.875rem' }}
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      {/* Posts Tab */}
      {tab === 'posts' && (
        <section>
          <h3>Posts</h3>
          {posts.map(p => (
            <div key={p._id} style={{ 
              padding: '1rem',
              borderBottom: '1px solid rgba(0,0,0,0.04)',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center'
            }}>
              <div>
                <strong>{p.title}</strong>
                <div style={{ fontSize: '0.9rem', color: '#718096' }}>
                  By {p.user?.username} — {formatDate(p.createdAt)}
                </div>
              </div>
              <div style={{ display: 'flex', gap: '0.5rem' }}>
                <Link to={`/post/${p.slug}`} className="btn btn-secondary" style={{ padding: '0.5rem 1rem', fontSize: '0.875rem' }}>
                  View
                </Link>
                <button 
                  onClick={() => handleDeletePost(p._id)}
                  className="btn btn-danger"
                  style={{ padding: '0.5rem 1rem', fontSize: '0.875rem' }}
                >
                  Delete
                </button>
              </div>
            </div>
          ))}
        </section>
      )}
    </div>
  );
};

export default Admin;
