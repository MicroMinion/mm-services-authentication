'use strict'

var assert = require('assert')
var events = require('events')
var inherits = require('inherits')
var utils = require('mm-create-identity')
var _ = require('lodash')
var async = require('async')

var SESSION_TIMEOUT_INTERVAL = 10 * 1000
var MAXIMUM_SESSION_TIME = 1000 * 60 * 5
var REPLY_TIMEOUT = 1000 * 10
var MAX_SEND_RETRIES = 3

var AuthenticationService = function (options) {
  assert(_.isObject(options))
  assert(_.isObject(options.platform))
  assert(_.isObject(options.logger))
  this.platform = options.platform
  this._log = options.logger
  this.platform.messaging.on('self.authentication.auth', this._onAuth.bind(this))
  this.platform.messaging.on('self.authentication.authResult', this._onAuthResult.bind(this))
  this.platform.messaging.on('friends.authentication.auth', this._onAuth.bind(this))
  this.platform.messaging.on('friends.authentication.authResult', this._onAuthResult.bind(this))
  this.platform.messaging.on('public.authentication.auth', this._onAuth.bind(this))
  this.platform.messaging.on('public.authentication.authResult', this._onAuthResult.bind(this))
  events.EventEmitter.call(this)
}

inherits(AuthenticationService, events.EventEmitter)

AuthenticationService.prototype._onAuth = function (topic, publicKey, data) {
  if (_.has(data, 'token') && data.token === this.__securityToken) {
    this._sendAuthResult(publicKey, true)
  } else {
    this._sendAuthResult(publicKey, false)
  }
  this._cleanupSession()
}

AuthenticationService.prototype._sendAuthResult = function (publicKey, success) {
  var self = this
  var retry = function (err) {
    if (err && success && self.__sendRetries < MAX_SEND_RETRIES) {
      async.setImmediate(function () {
        self._sendAuthResult(publicKey, success)
      })
      self.__sendRetries = self.__sendRetries + 1
    } else if (err) {
      self.emit('authResult', 'can not send confirmation', null)
    } else if (!success) {
      self.emit('authResult', 'other side provided wrong code', null)
    } else if (success) {
      self.emit('authResult', null, publicKey)
    } else {
      self._log.error('reached point that should not be reached in authentication protocol')
    }
  }
  this.platform.messaging.send('authentication.authResult', publicKey, {
    success: success
  }, {
    callback: retry
  })
}

AuthenticationService.prototype._onAuthResult = function (topic, publicKey, data) {
  if (publicKey === this.__remotePublicKey) {
    if (data.success) {
      this.emit('authResult', null, publicKey)
    } else {
      this.emit('authResult', 'authentication failed', null)
    }
  }
}

AuthenticationService.prototype.startSession = function () {
  this._cleanupSession()
  this.__securityToken = utils.createShortSecret()
  this._startSessionTimer()
}

AuthenticationService.prototype._cleanupSession = function () {
  clearTimeout(this.__sessionTimeout)
  clearTimeout(this.__replyTimeout)
  this.__remotePublicKey = undefined
  this.__remoteSecurityToken = undefined
  this.__securityToken = undefined
  this.__extendSession = false
  this._sessionExtensions = 0
  this.__sendRetries = 0
}

AuthenticationService.prototype._maxSessionTimeReached = function () {
  return (this._sessionExtensions + 1) * SESSION_TIMEOUT_INTERVAL > MAXIMUM_SESSION_TIME
}

AuthenticationService.prototype._startSessionTimer = function () {
  var self = this
  this.__sessionTimeout = setTimeout(function () {
    if (self.__extendSession && !self._maxSessionTimeReached()) {
      self._extendSession = false
      process.nextTick(self._startSessionTimer.bind(self))
    } else {
      self._cleanupSession()
    }
  }, SESSION_TIMEOUT_INTERVAL)
}

AuthenticationService.prototype.extendSession = function () {
  this.__extendSession = true
}

AuthenticationService.prototype.isActive = function () {
  return _.isString(this.__securityToken)
}

AuthenticationService.prototype.getToken = function () {
  if (this.__securityToken) {
    return this.__securityToken
  } else {
    throw new Error('Session not active. Use startSession first')
  }
}

AuthenticationService.prototype.authenticate = function (publicKey, securityToken) {
  var self = this
  this.__remotePublicKey = publicKey
  this.__remoteSecurityToken = securityToken
  var callback = function (err) {
    if (err) {
      self.emit('authResult', 'failed to send message', null)
      self._cleanupSession()
    }
  }
  this.platform.messaging.send('authentication.auth', publicKey, {
    token: securityToken
  }, {
    callback: callback,
    realtime: true
  })
  this.__replyTimeout = setTimeout(function () {
    self.emit('authResult', 'no reply received', null)
    self._cleanupSession()
  }, REPLY_TIMEOUT)
}

module.exports = AuthenticationService
