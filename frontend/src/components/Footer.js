import React from 'react';

const Footer = () => {
  return (
    <footer className="footer">
      <div className="container">
        <p>&copy; {new Date().getFullYear()} MyBlog. All rights reserved. Built with security in mind.</p>
      </div>
    </footer>
  );
};

export default Footer;
