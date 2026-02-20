const mongoose = require('mongoose');

const postSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  title: {
    type: String,
    required: [true, 'Title is required'],
    trim: true,
    minlength: [3, 'Title must be at least 3 characters'],
    maxlength: [255, 'Title cannot exceed 255 characters']
  },
  slug: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  body: {
    type: String,
    required: [true, 'Body is required'],
    minlength: [5, 'Body must be at least 5 characters']
  },
  imagePath: {
    type: String,
    default: null
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: null
  }
});

postSchema.statics.createSlug = function(title) {
  const baseSlug = title
    .toLowerCase()
    .replace(/[^a-z0-9]+/gi, '-')
    .replace(/^-|-$/g, '');
  const uniqueId = Math.random().toString(36).substring(2, 8);
  return `${baseSlug}-${uniqueId}`;
};

postSchema.index({ user: 1, createdAt: -1 });

const Post = mongoose.model('Post', postSchema);

module.exports = Post;
