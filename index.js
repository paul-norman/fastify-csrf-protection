'use strict'

const assert		= require('node:assert');
const fp			= require('fastify-plugin');
const CSRF			= require('@fastify/csrf');
const createError	= require('@fastify/error');

const MissingCSRFSecretError	= createError('FST_CSRF_MISSING_SECRET', 'Missing csrf secret', 403);
const InvalidCSRFTokenError		= createError('FST_CSRF_INVALID_TOKEN', 'Invalid csrf token', 403);

const defaultOptions = {
	cookieKey:		'_csrf',
	cookieOpts:		{ path: '/', sameSite: true, httpOnly: true },
	sessionKey: 	'_csrf',
	csrfProtection:	csrfProtectionDefault,
	getToken:		getTokenDefault,
	getUserInfo:	getUserInfoDefault,
	sessionPlugin:	'@fastify/cookie'
}

async function fastifyCsrfProtection(fastify, opts) {
	const {
		cookieKey,
		cookieOpts,
		sessionKey,
		csrfProtection,
		getToken,
		getUserInfo,
		sessionPlugin
	} = Object.assign({}, defaultOptions, opts);

	const csrfOpts = opts && opts.csrfOpts ? opts.csrfOpts : {};

	assert(typeof cookieKey === 'string', 'cookieKey should be a string');
	assert(typeof sessionKey === 'string', 'sessionKey should be a string');
	assert(typeof csrfProtection === 'function', 'csrfProtection should be a function');
	assert(typeof getToken === 'function', 'getToken should be a function');
	assert(typeof getUserInfo === 'function', 'getUserInfo should be a function');
	assert(typeof cookieOpts === 'object', 'cookieOpts should be a object');
	assert(
		['@fastify/cookie', '@fastify/session', '@fastify/secure-session'].includes(sessionPlugin),
		"sessionPlugin should be one of the following: '@fastify/cookie', '@fastify/session', '@fastify/secure-session'"
	);

	if (opts.getUserInfo) {
		csrfOpts.userInfo = true;
	}

	if (sessionPlugin === '@fastify/cookie' && csrfOpts.userInfo) {
		assert(csrfOpts.hmacKey, 'csrfOpts.hmacKey is required');
	}

	const tokens = new CSRF(csrfOpts);

	const isCookieSigned = cookieOpts && cookieOpts.signed;

	if (sessionPlugin === '@fastify/secure-session') {
		fastify.decorateReply('generateCsrf', generateCsrfSecureSession);
	} else if (sessionPlugin === '@fastify/session') {
		fastify.decorateReply('generateCsrf', generateCsrfSession);
	} else {
		fastify.decorateReply('generateCsrf', generateCsrfCookie);
	}

	fastify.decorate('csrfProtection', csrfProtection);
	fastify.decorate('checkCsrf', checkCsrf);

	let getSecret;
	if (sessionPlugin === '@fastify/secure-session') {
		getSecret = function getSecret(request, reply) {
			return request.session.get(sessionKey);
		};
	} else if (sessionPlugin === '@fastify/session') {
		getSecret = function getSecret(request, reply) {
			return request.session[sessionKey];
		};
	} else {
		getSecret = function getSecret(request, reply) {
			return isCookieSigned
				? reply.unsignCookie(request.cookies[cookieKey] || '').value
				: request.cookies[cookieKey]
		};
	}

	function generateCsrfCookie(opts) {
		let secret = isCookieSigned
			? this.unsignCookie(this.request.cookies[cookieKey] || '').value
			: this.request.cookies[cookieKey];

		const userInfo = opts ? opts.userInfo : undefined;

		if (!secret) {
			secret = tokens.secretSync();
			this.setCookie(cookieKey, secret, Object.assign({}, cookieOpts, opts));
		}

		return tokens.create(secret, userInfo);
	}

	function generateCsrfSecureSession(opts) {
		let secret = this.request.session.get(sessionKey);
		if (!secret) {
			secret = tokens.secretSync();
			this.request.session.set(sessionKey, secret);
		}

		const userInfo = opts ? opts.userInfo : undefined;

		if (opts) {
			this.request.session.options(opts);
		}

		return tokens.create(secret, userInfo);
	}

	function generateCsrfSession(opts) {
		let secret = this.request.session[sessionKey];
		if (!secret) {
			secret = tokens.secretSync()
			this.request.session[sessionKey] = secret;
		}

		const userInfo = opts ? opts.userInfo : undefined;

		return tokens.create(secret, userInfo);
	}

	function checkCsrf(request, reply) {
		const secret = getSecret(request, reply);
		if (!secret) {
			request.log.warn('Missing csrf secret');
			throw new MissingCSRFSecretError();
		}

		if (!tokens.verify(secret, getToken(request), getUserInfo(request))) {
			request.log.warn('Invalid csrf token');
			throw new InvalidCSRFTokenError();
		}
	}
}

function getTokenDefault(request) {
	return (request.body && request.body._csrf) ||
		request.headers['csrf-token'] ||
		request.headers['xsrf-token'] ||
		request.headers['x-csrf-token'] ||
		request.headers['x-xsrf-token'];
}

function getUserInfoDefault(request) {
	return undefined
}

function csrfProtectionDefault(request, reply, next) {
	try {
		this.checkCsrf(request, reply);
	} catch(e) {
		return reply.send(e);
	}

	next();
}

module.exports = fp(fastifyCsrfProtection, {
	fastify: '4.x',
	name: '@fastify/csrf-protection'
})
module.exports.default = fastifyCsrfProtection
module.exports.fastifyCsrfProtection = fastifyCsrfProtection