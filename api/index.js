/**
 * api/index.js — Vercel Serverless Function Entry Point for AuthLens
 * Routes incoming serverless HTTP requests to the Express application.
 */
const app = require('../backend/app');

module.exports = (req, res) => {
  try {
    return app(req, res);
  } catch (err) {
    console.error('[VERCEL HANDLER EXCEPTION]:', {
      message: err.message,
      code: err.code,
    });
    if (!res.headersSent) {
      res.status(500).json({ error: 'Serverless execution error.' });
    }
  }
};
