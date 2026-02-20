import React from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

const Header = () => {
  const { user, isAuthenticated, isAdmin, canCreatePosts, logout } = useAuth();

  return (
    <header className="header">
      <div className="container">
        <div className="header-content">
          <Link to="/" className="logo">MyBlog</Link>
          <nav>
            <ul className="nav-links">
              <li><Link to="/">Home</Link></li>
              {isAuthenticated ? (
                <>
                  <li><Link to="/dashboard">Dashboard</Link></li>
                  <li><Link to="/profile">Profile</Link></li>
                  {isAdmin && <li><Link to="/admin">Admin</Link></li>}
                  <li>
                    <Link to="/" onClick={(e) => { e.preventDefault(); logout(); }}>
                      Logout
                    </Link>
                  </li>
                </>
              ) : (
                <>
                  <li><Link to="/login">Login</Link></li>
                  <li><Link to="/register">Register</Link></li>
                </>
              )}
            </ul>
          </nav>
        </div>
      </div>
    </header>
  );
};

export default Header;
