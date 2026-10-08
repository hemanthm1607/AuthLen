/**
 * api/index.js — Vercel Serverless Function Entry Point for AuthLens
 * Routes incoming serverless HTTP requests to the Express application.
 */
const app = require('../backend/app');

module.exports = (req, res) => {
  return app(req, res);
};
