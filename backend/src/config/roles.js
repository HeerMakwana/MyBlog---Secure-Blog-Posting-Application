/**
 * Role-Based Access Control (RBAC) Configuration
 * Implements least privilege principle with 4 user roles
 */

// Role definitions - ordered by privilege level (lowest to highest)
const ROLES = {
  GUEST: 'guest',           // Unauthenticated users - read-only public content
  CUSTOMER: 'customer',     // Authenticated users - can manage own profile
  EDITOR: 'editor',         // Content creators - can create/edit own posts
  ADMINISTRATOR: 'administrator'  // Full access - system management
};

// Role hierarchy - higher roles inherit permissions from lower roles
const ROLE_HIERARCHY = {
  [ROLES.GUEST]: 0,
  [ROLES.CUSTOMER]: 1,
  [ROLES.EDITOR]: 2,
  [ROLES.ADMINISTRATOR]: 3
};

// Permission definitions
const PERMISSIONS = {
  // Public permissions
  VIEW_PUBLIC_POSTS: 'view_public_posts',
  VIEW_PUBLIC_PROFILES: 'view_public_profiles',
  
  // Customer permissions
  VIEW_OWN_PROFILE: 'view_own_profile',
  EDIT_OWN_PROFILE: 'edit_own_profile',
  CHANGE_OWN_PASSWORD: 'change_own_password',
  ENABLE_MFA: 'enable_mfa',
  DISABLE_MFA: 'disable_mfa',
  
  // Editor permissions
  CREATE_POST: 'create_post',
  EDIT_OWN_POST: 'edit_own_post',
  DELETE_OWN_POST: 'delete_own_post',
  VIEW_OWN_POSTS: 'view_own_posts',
  
  // Administrator permissions
  VIEW_ALL_USERS: 'view_all_users',
  EDIT_ANY_USER: 'edit_any_user',
  DELETE_ANY_USER: 'delete_any_user',
  CHANGE_USER_ROLE: 'change_user_role',
  VIEW_ALL_POSTS: 'view_all_posts',
  EDIT_ANY_POST: 'edit_any_post',
  DELETE_ANY_POST: 'delete_any_post',
  VIEW_AUDIT_LOGS: 'view_audit_logs',
  VIEW_ADMIN_STATS: 'view_admin_stats',
  MANAGE_SYSTEM: 'manage_system'
};

// Permission matrix - maps roles to their allowed permissions
const PERMISSION_MATRIX = {
  [ROLES.GUEST]: [
    PERMISSIONS.VIEW_PUBLIC_POSTS,
    PERMISSIONS.VIEW_PUBLIC_PROFILES
  ],
  
  [ROLES.CUSTOMER]: [
    // Inherits GUEST permissions
    PERMISSIONS.VIEW_PUBLIC_POSTS,
    PERMISSIONS.VIEW_PUBLIC_PROFILES,
    // Own permissions
    PERMISSIONS.VIEW_OWN_PROFILE,
    PERMISSIONS.EDIT_OWN_PROFILE,
    PERMISSIONS.CHANGE_OWN_PASSWORD,
    PERMISSIONS.ENABLE_MFA,
    PERMISSIONS.DISABLE_MFA
  ],
  
  [ROLES.EDITOR]: [
    // Inherits CUSTOMER permissions
    PERMISSIONS.VIEW_PUBLIC_POSTS,
    PERMISSIONS.VIEW_PUBLIC_PROFILES,
    PERMISSIONS.VIEW_OWN_PROFILE,
    PERMISSIONS.EDIT_OWN_PROFILE,
    PERMISSIONS.CHANGE_OWN_PASSWORD,
    PERMISSIONS.ENABLE_MFA,
    PERMISSIONS.DISABLE_MFA,
    // Own permissions
    PERMISSIONS.CREATE_POST,
    PERMISSIONS.EDIT_OWN_POST,
    PERMISSIONS.DELETE_OWN_POST,
    PERMISSIONS.VIEW_OWN_POSTS
  ],
  
  [ROLES.ADMINISTRATOR]: [
    // Full access - all permissions
    ...Object.values(PERMISSIONS)
  ]
};

/**
 * Check if a role has a specific permission
 * @param {string} role - User's role
 * @param {string} permission - Permission to check
 * @returns {boolean}
 */
const hasPermission = (role, permission) => {
  if (!role || !PERMISSION_MATRIX[role]) {
    return false; // Fail-safe: deny access if role is invalid
  }
  return PERMISSION_MATRIX[role].includes(permission);
};

/**
 * Check if a role meets minimum required level
 * @param {string} userRole - User's current role
 * @param {string} requiredRole - Minimum required role
 * @returns {boolean}
 */
const hasMinimumRole = (userRole, requiredRole) => {
  const userLevel = ROLE_HIERARCHY[userRole] ?? -1;
  const requiredLevel = ROLE_HIERARCHY[requiredRole] ?? Infinity;
  return userLevel >= requiredLevel;
};

/**
 * Get all permissions for a role
 * @param {string} role - User's role
 * @returns {string[]}
 */
const getRolePermissions = (role) => {
  return PERMISSION_MATRIX[role] || [];
};

/**
 * Validate if a role is valid
 * @param {string} role - Role to validate
 * @returns {boolean}
 */
const isValidRole = (role) => {
  return Object.values(ROLES).includes(role);
};

/**
 * Get the default role for new users (least privilege)
 * @returns {string}
 */
const getDefaultRole = () => {
  return ROLES.CUSTOMER; // Lowest authenticated role
};

module.exports = {
  ROLES,
  ROLE_HIERARCHY,
  PERMISSIONS,
  PERMISSION_MATRIX,
  hasPermission,
  hasMinimumRole,
  getRolePermissions,
  isValidRole,
  getDefaultRole
};
