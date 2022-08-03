async function importKey(secret) {
	return await crypto.subtle.importKey(
	  'raw',
	  new TextEncoder().encode(secret),
	  { name: 'HMAC', hash: 'SHA-256' },
	  false,
	  ['sign', 'verify'],
	)
  }

  async function sign(value, secret) {
    
	const key = await importKey(secret)
	const signature = await crypto.subtle.sign(
	  'HMAC',
	  key,
	  new TextEncoder().encode(value),
	)
    const signatureBase64 = btoa(String.fromCharCode(...new Uint8Array(signature)))
	return encodeURIComponent(`${value}|${signatureBase64}`)

  }

  async function verify(encodedSignedValue, secret) {
    const [value, signatureBase64] = decodeURIComponent(encodedSignedValue).split('|')
    console.log("values", value, signatureBase64)
	const key = await importKey(secret)
	const signatureBuffer = Uint8Array.from(atob(signatureBase64), c => c.charCodeAt(0))

	return await crypto.subtle.verify(
		'HMAC',
		key,
		signatureBuffer,
		new TextEncoder().encode(value)
	)
  }

export { sign, verify }