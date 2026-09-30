/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { AllHtmlEntities as Entities } from 'html-entities'
import config from 'config'
import fs from 'node:fs/promises'

import * as challengeUtils from '../lib/challengeUtils'
import { themes } from '../views/themes/themes'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'

const entities = new Entities()

function favicon () {
  return utils.extractFilename(config.get('application.favicon'))
}

function sanitizeUsername (val: string): string {
  let sanitized = (val || '').replace(/[\r\n\u2028\u2029]+/g, ' ')
  sanitized = sanitized.replace(/\\*([!#][{\[])/g, '\\$1')
  if (!sanitized.startsWith('\\')) {
    sanitized = '\\' + sanitized
  }
  return sanitized
}

export function getUserProfile () {
  return async (req: Request, res: Response, next: NextFunction) => {
    let template: string
    try {
      template = await fs.readFile('views/userProfile.pug', { encoding: 'utf-8' })
    } catch (err) {
      next(err)
      return
    }

    const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
    if (!loggedInUser) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress)); return
    }

    let user: UserModel | null
    try {
      user = await UserModel.findByPk(loggedInUser.data.id)
    } catch (error) {
      next(error)
      return
    }

    if (!user) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      return
    }

    let username = user.username

    const match = username?.match(/^#{(.*)}$/)
    if (match !== null && match !== undefined && utils.isChallengeEnabled(challenges.usernameXssChallenge)) {
      req.app.locals.abused_ssti_bug = true
      const code = match[1]
      try {
        if (!code) {
          throw new Error('Username is null')
        }
        const singleQuoteRegex = /^'(?:[^'\\]|\\.)*'$/
        const doubleQuoteRegex = /^"(?:[^"\\]|\\.)*"$/
        const backtickRegex = /^`(?:[^`\\$]|\\.|\$(?!{))*`$/
        const arithmeticRegex = /^[0-9 +*/%().-]+$/
        const booleanRegex = /^(?:true|false|null|undefined)$/

        const isSafe = singleQuoteRegex.test(code) ||
          doubleQuoteRegex.test(code) ||
          backtickRegex.test(code) ||
          (arithmeticRegex.test(code) && /\d/.test(code)) ||
          booleanRegex.test(code)

        if (!isSafe) {
          throw new Error('Unsafe code execution blocked')
        }
        username = String(eval(code)) // eslint-disable-line no-eval
      } catch (err) {
        username = sanitizeUsername(user.username ?? '')
      }
    } else {
      if (username?.match(/#{(.*)}/) !== null && utils.isChallengeEnabled(challenges.usernameXssChallenge)) {
        req.app.locals.abused_ssti_bug = true
      }
      username = sanitizeUsername(username ?? '')
    }

    const themeKey = config.get<string>('application.theme') as keyof typeof themes
    const theme = themes[themeKey] || themes['bluegrey-lightgreen']

    if (username) {
      template = template.replace(/_username_/g, username)
    }
    template = template.replace(/_emailHash_/g, security.hash(user?.email))
    template = template.replace(/_title_/g, entities.encode(config.get<string>('application.name')))
    template = template.replace(/_favicon_/g, favicon())
    template = template.replace(/_bgColor_/g, theme.bgColor)
    template = template.replace(/_textColor_/g, theme.textColor)
    template = template.replace(/_navColor_/g, theme.navColor)
    template = template.replace(/_primLight_/g, theme.primLight)
    template = template.replace(/_primDark_/g, theme.primDark)
    template = template.replace(/_logo_/g, utils.extractFilename(config.get('application.logo')))

    try {
      const pug = (await import('pug')).default
      const fn = pug.compile(template)
      const CSP = `img-src 'self' ${user?.profileImage}; script-src 'self' 'unsafe-eval'`

      challengeUtils.solveIf(challenges.usernameXssChallenge, () => {
        return username && user?.profileImage.match(/;[ ]*script-src(.)*'unsafe-inline'/g) !== null && utils.contains(username, '<script>alert(`xss`)</script>')
      })

      res.set({
        'Content-Security-Policy': CSP
      })

      res.send(fn(user))
    } catch (err) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
    }
  }
}
