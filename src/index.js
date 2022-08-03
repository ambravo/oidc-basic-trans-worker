import { Router } from 'itty-router'
import { parse } from 'cookie'

import { sign,verify } from './cookie-signer'

const auth = {
	domain: AUTH0_DOMAIN,
	clientId: AUTH0_CLIENT_ID,
	clientSecret: AUTH0_CLIENT_SECRET,
	callbackUrl: AUTH0_CALLBACK_URL
  }

const index_html = `
<!DOCTYPE html>
<html>
<body>
	<button type="button" onclick="window.location.href='/login'">Login</button>
</body>
</html>
`

const COOKIE_NAME = '_a0gg_token'

const newCookie = async (value) => {
	  const expires = new Date()
	  expires.setHours(expires.getHours() + 3)
	  const signed = await sign(value+"%"+expires.toUTCString(), COOKIE_SECRET)
	  return `${COOKIE_NAME}=${signed}; Expires=${expires.toUTCString()}; Secure; HttpOnly`
}
const router = Router()

const getA0Cookie = async (request) => {
	  const cookie = request.headers.get('Cookie')
	  if (cookie) {
		const parsed = parse(cookie)
		const decodedA0Cookie = parsed[COOKIE_NAME]
		const signedExpiration = Date.parse(decodedA0Cookie.split('|')[0].split('%')[1])
		const now = Date.now()
		if (signedExpiration < now) {
			console.error("EXPIRED COOKIE", expires, now)
			return null
		}
		const codedA0Cookie = encodeURIComponent(decodedA0Cookie)
		if (codedA0Cookie && await verify(codedA0Cookie, COOKIE_SECRET)) {
			return true
		}
		return null
	  }
	  return null
}

router.get("/login", async (request) => {
	  const rayid = request.headers.get('cf-ray')
	  const a0loginUrl = `https://${auth.domain}/authorize?response_type=code&client_id=${auth.clientId}&redirect_uri=${auth.callbackUrl}&scope=openid%20profile%20email&state=${encodeURIComponent(rayid)}&rayid=${encodeURIComponent(rayid)}`
	  return Response.redirect(a0loginUrl, 302)
})

router.get("/callback", async (request) => {
	  const code = request.url.split("code=")[1].split("&")[0]
	  const tokenUrl = `https://${auth.domain}/oauth/token`
	  const tokenResponse = await fetch(tokenUrl, {
		method: "POST",
		headers: {
		  "Content-Type": "application/json",
		},
		body: JSON.stringify({
		  grant_type: "authorization_code",
		  client_id: auth.clientId,
		  client_secret: auth.clientSecret,
		  code,
		  redirect_uri: auth.callbackUrl,
		}),
	  })
	  
	  const token = await tokenResponse.json()
	  const cookie = await newCookie(token.access_token)
	  let rootUrl = request.url.split("/callback")[0] + "/ui/"
	  return new Response(null, {
		status: 302,
		headers: {
			'Location': rootUrl,
			'Set-Cookie': cookie
		}
	});
})

router.all("/function/*", async (request) => {
	const response = await fetch(request)
	return response
	}
)
router.all("*", async (request) => {
	const a0Cookie = await getA0Cookie(request)
	if (a0Cookie) {
		const response = await fetch(request.url,{method: request.method, 
			headers: { ...request.headers, 
				"Authorization": `Basic ${btoa(FAAS_USER+':'+FAAS_PASSWORD)}`,
				"Set-Cookie": a0Cookie
			},
			body: request.body})
		return response;
	} else {
		return new Response(index_html, { status: 200, headers: { 'Content-Type': 'text/html' } })
	}
})

addEventListener('fetch', event => {
	event.respondWith(router.handle(event.request))
  })