import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { useAuth } from './context/AuthContext';

// Components
import Header from './components/Header';
import Footer from './components/Footer';
import PrivateRoute from './components/PrivateRoute';
import AdminRoute from './components/AdminRoute';

// Pages
import Home from './pages/Home';
import Login from './pages/Login';
import Register from './pages/Register';
import Dashboard from './pages/Dashboard';
import Profile from './pages/Profile';
import CreatePost from './pages/CreatePost';
import EditPost from './pages/EditPost';
import ViewPost from './pages/ViewPost';
import EnableMFA from './pages/EnableMFA';
import DisableMFA from './pages/DisableMFA';
import MFAVerify from './pages/MFAVerify';
import Admin from './pages/Admin';

function App() {
  const { loading } = useAuth();

  if (loading) {
    return (
      <div style={{ 
        display: 'flex', 
        justifyContent: 'center', 
        alignItems: 'center', 
        height: '100vh' 
      }}>
        <div className="spinner" style={{ 
          borderTopColor: '#667eea',
          width: '40px',
          height: '40px'
        }}></div>
      </div>
    );
  }

  return (
    <Router>
      <div className="App">
        <Header />
        <main className="container">
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/login" element={<Login />} />
            <Route path="/register" element={<Register />} />
            <Route path="/mfa-verify" element={<MFAVerify />} />
            <Route path="/post/:slug" element={<ViewPost />} />
            
            {/* Protected Routes */}
            <Route path="/dashboard" element={
              <PrivateRoute><Dashboard /></PrivateRoute>
            } />
            <Route path="/profile" element={
              <PrivateRoute><Profile /></PrivateRoute>
            } />
            <Route path="/create-post" element={
              <PrivateRoute><CreatePost /></PrivateRoute>
            } />
            <Route path="/edit-post/:id" element={
              <PrivateRoute><EditPost /></PrivateRoute>
            } />
            <Route path="/enable-mfa" element={
              <PrivateRoute><EnableMFA /></PrivateRoute>
            } />
            <Route path="/disable-mfa" element={
              <PrivateRoute><DisableMFA /></PrivateRoute>
            } />
            
            {/* Admin Routes */}
            <Route path="/admin" element={
              <AdminRoute><Admin /></AdminRoute>
            } />
          </Routes>
        </main>
        <Footer />
      </div>
    </Router>
  );
}

export default App;
