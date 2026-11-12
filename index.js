import express from 'express'
import { MongoClient, ObjectId } from 'mongodb'
import cors from 'cors'
import 'dotenv/config'
import { createRemoteJWKSet, jwtVerify } from 'jose'
import { randomUUID } from 'node:crypto'

const app = express()
const PORT = 7000
const CLIENT_URLS = (process.env.CLIENT_URL).split(',').map((s) => s.trim())
const CATEGORIES = ['Photo Studio', 'Video Production', 'Podcast Lounge', 'Design & Motion', 'Workshop']

app.use(cors({ origin: CLIENT_URLS, credentials: true }))
app.use(express.json({ limit: '1mb' }))

const client = new MongoClient(process.env.MONGODB_URI)

export async function connectToMongoDB() {
    try {
        await client.connect()
        console.log('You successfully connected to MongoDB!')
        return client
    } catch (err) {
        console.dir(err)
        throw err
    }
}
const mongoClient = await connectToMongoDB()
const db = mongoClient.db('studiospace')

const studioCollection = db.collection('studios')
const bookingCollection = db.collection('bookings')
const wishlistCollection = db.collection('wishlists')


const sessionCollection = db.collection('session')
const userCollection = db.collection('user')

await Promise.all([
    studioCollection.createIndex({ ownerEmail: 1 }),
    studioCollection.createIndex({ category: 1, rating: -1 }),
    bookingCollection.createIndex({ studioId: 1, date: 1, status: 1 }),
    bookingCollection.createIndex({ guestEmail: 1 }),
    bookingCollection.createIndex({ hostEmail: 1 }),
    wishlistCollection.createIndex({ userEmail: 1, studioId: 1 }, { unique: true }),
])

/* ===================== UTILS ===================== */

class HttpError extends Error {
    constructor(status, message) {
        super(message)
        this.status = status
    }
}

// Helper: valid 24-hex ids become ObjectIds, anything else is null.
function objectId(id) {
    return typeof id === 'string' && /^[a-f\d]{24}$/i.test(id) ? new ObjectId(id) : null
}
const mustObjectId = (id, label = 'id') => {
    const _id = objectId(String(id))
    if (!_id) throw new HttpError(400, `Invalid ${label}.`)
    return _id
}
const escapeRegex = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
const str = (v) => (typeof v === 'string' ? v.trim() : '')
const isUrl = (v) => /^https?:\/\/\S+$/i.test(v)

function toMinutes(time) {
    const m = /^([01]\d|2[0-3]):([0-5]\d)$/.exec(String(time))
    if (!m) throw new HttpError(400, 'Time must be in HH:MM format.')
    return Number(m[1]) * 60 + Number(m[2])
}

// Validates + sanitises a studio body. Owner fields come from the token, never from the body.
function parseStudioBody(body = {}) {
    const title = str(body.title)
    const category = str(body.category)
    const location = str(body.location)
    const image = str(body.image)
    const overview = str(body.overview)
    const hourlyRate = Number(body.hourlyRate)
    const securityDeposit = Number(body.securityDeposit)
    const maxCapacity = Number(body.maxCapacity)

    if (title.length < 3) throw new HttpError(400, 'Title must be at least 3 characters.')
    if (!CATEGORIES.includes(category)) throw new HttpError(400, 'Please choose a valid category.')
    if (!(hourlyRate > 0)) throw new HttpError(400, 'Hourly rate must be greater than 0.')
    if (!(securityDeposit >= 0)) throw new HttpError(400, 'Security deposit cannot be negative.')
    if (!Number.isInteger(maxCapacity) || maxCapacity < 1) throw new HttpError(400, 'Max capacity must be a whole number of at least 1.')
    if (location.length < 3) throw new HttpError(400, 'Please enter the studio location.')
    if (!isUrl(image)) throw new HttpError(400, 'Please provide a valid image URL.')
    if (overview.length < 20) throw new HttpError(400, 'Overview must be at least 20 characters.')

    const amenities = Array.isArray(body.amenities) ? [...new Set(body.amenities.map(str).filter(Boolean))].slice(0, 30) : []
    const gallery = Array.isArray(body.gallery) ? body.gallery.map(str).filter(isUrl).slice(0, 8) : []
    return { title, category, hourlyRate, securityDeposit, maxCapacity, location, image, overview, amenities, gallery }
}

/* ===================== AUTH MIDDLEWARE ===================== */

// better-auth (Next side) publishes its signing keys here — the JWT middleware
// verifies incoming Bearer tokens against this key set. Override with
// JWKS_URL when running the backend against a different frontend host.
const JWKS = createRemoteJWKSet(
    new URL(process.env.JWKS_URL ?? `${CLIENT_URLS[0]}/api/auth/jwks`)
)

// Reads the HTTPOnly better-auth session cookie (works when requests are proxied through the Next origin).
function cookieValue(req, names) {
    for (const part of (req.headers.cookie ?? '').split(';')) {
        const [name, ...rest] = part.trim().split('=')
        if (names.includes(name)) return decodeURIComponent(rest.join('='))
    }
    return null
}
const sessionCookie = (req) => cookieValue(req, ['better-auth.session_token', '__Secure-better-auth.session_token'])
// The JWT the Next app issues at /api/token — an HS256 token signed with the shared JWT_SECRET.
const studiospaceCookie = (req) => cookieValue(req, ['studiospace_token'])

export const verifyToken = async (req, res, next) => {
    const authHeader = req.headers.authorization
    const bearer = authHeader?.startsWith('Bearer ')
        ? authHeader.slice('Bearer '.length).trim()
        : null
    const studiospaceJwt = studiospaceCookie(req)
    const sessionToken0 = sessionCookie(req)
    const token = bearer ?? studiospaceJwt ?? sessionToken0

    if (!token) {
        return res.status(401).send({ message: 'Unauthorized: please log in to continue.' })
    }

    const resolveUser = async (userId) => {
        // better-auth users may be stored with ObjectId or string ids; accept either form.
        const id = String(userId)
        const _id = objectId(id)
        return userCollection.findOne({ _id: { $in: _id ? [_id, id] : [id] } })
    }
    const asReqUser = (user) => ({ id: String(user._id), email: user.email, name: user.name ?? 'Creator', image: user.image })

    // Path 1: a Bearer JWT signed by better-auth (verified against its published JWKS).
    if (bearer) {
        try {
            const { payload } = await jwtVerify(bearer, JWKS)
            const user = await resolveUser(payload.sub)
            if (!user) {
                return res.status(401).send({ message: 'User for this token no longer exists.' })
            }
            req.user = asReqUser(user)
            return next()
        } catch {
            // Not a JWKS-verifiable JWT (or expired) — fall through to the session-token lookup.
        }
    }

    // Path 2: the studiospace_token HTTPOnly cookie — HS256 JWT minted by the Next app's
    // /api/token route. Requires the same JWT_SECRET as the frontend's .env.
    if (studiospaceJwt && process.env.JWT_SECRET) {
        try {
            const { payload } = await jwtVerify(studiospaceJwt, new TextEncoder().encode(process.env.JWT_SECRET))
            const user = await resolveUser(payload.sub)
            if (!user) {
                return res.status(401).send({ message: 'User for this token no longer exists.' })
            }
            req.user = asReqUser(user)
            return next()
        } catch {
            // Invalid/expired JWT — fall through to the session-token lookup.
        }
    }

    // Fallback: raw better-auth session token ("token.signature" cookie value).
    const sessionToken = token.split('.')[0]
    const session = await sessionCollection.findOne({ token: sessionToken })
    if (!session || new Date(session.expiresAt) < new Date()) {
        return res.status(401).send({ message: 'Invalid or expired token.' })
    }

    const user = await resolveUser(session.userId)
    if (!user) {
        return res.status(401).send({ message: 'User for this session no longer exists.' })
    }

    req.user = asReqUser(user)
    next()
}

/* ===================== STUDIOS ===================== */

const NO_REVIEWS = { projection: { reviews: 0 } }

// Public: list + search + filter + sort + pagination
app.get('/api/studios', async (req, res) => {
    const { search, category, sort = 'newest', minPrice, maxPrice } = req.query
    const page = Math.max(1, Number(req.query.page) || 1)
    const limit = Math.min(48, Math.max(1, Number(req.query.limit) || 9))

    const filter = {}
    if (category && category !== 'all') filter.category = String(category)
    if (search && String(search).trim()) {
        const rx = new RegExp(escapeRegex(String(search).trim()), 'i')
        filter.$or = [{ title: rx }, { location: rx }, { overview: rx }, { amenities: rx }]
    }
    if (minPrice || maxPrice) {
        filter.hourlyRate = {}
        if (minPrice) filter.hourlyRate.$gte = Number(minPrice)
        if (maxPrice) filter.hourlyRate.$lte = Number(maxPrice)
    }
    const sortMap = {
        newest: { createdAt: -1 },
        rating: { rating: -1, reviewCount: -1 },
        'price-asc': { hourlyRate: 1 },
        'price-desc': { hourlyRate: -1 },
    }

    const [items, total] = await Promise.all([
        studioCollection.find(filter, NO_REVIEWS).sort(sortMap[sort] ?? sortMap.newest).skip((page - 1) * limit).limit(limit).toArray(),
        studioCollection.countDocuments(filter),
    ])
    res.send({ items, total, page, pages: Math.max(1, Math.ceil(total / limit)) })
})

// Public: home page — 6 top-rated / newest studios
app.get('/api/studios/featured', async (req, res) => {
    const result = await studioCollection.find({}, NO_REVIEWS).sort({ rating: -1, createdAt: -1 }).limit(6).toArray()
    res.send(result)
})

// Studios owned by the logged-in user
app.get('/api/studios/mine', verifyToken, async (req, res) => {
    const result = await studioCollection.find({ ownerEmail: req.user.email }, NO_REVIEWS).sort({ createdAt: -1 }).toArray()
    res.send(result)
})

// Public: guests can browse details without logging in.
app.get('/api/studios/:id', async (req, res) => {
    const _id = objectId(req.params.id)
    if (!_id) return res.status(400).send({ message: 'Invalid studio id.' })

    const result = await studioCollection.findOne({ _id })
    if (!result) return res.status(404).send({ message: 'Studio not found.' })
    res.send(result)
})

// Public: confirmed slots for a date (live availability in the booking modal)
app.get('/api/studios/:id/availability', async (req, res) => {
    const _id = objectId(req.params.id)
    if (!_id) return res.status(400).send({ message: 'Invalid studio id.' })
    const date = String(req.query.date ?? '')
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return res.status(400).send({ message: 'Date must be YYYY-MM-DD.' })

    const slots = await bookingCollection
        .find({ studioId: _id, date, status: 'Confirmed' }, { projection: { startTime: 1, endTime: 1 } })
        .sort({ startMin: 1 })
        .toArray()
    res.send(slots.map((s) => ({ startTime: s.startTime, endTime: s.endTime })))
})

// The owner is stamped from the token server-side, so nobody can list under someone else's account.
app.post('/api/studios', verifyToken, async (req, res) => {
    const data = parseStudioBody(req.body)
    const now = new Date()
    const doc = {
        ...data,
        ownerEmail: req.user.email,
        ownerName: req.user.name,
        ownerImage: req.user.image,
        rating: 0,
        reviewCount: 0,
        reviews: [],
        createdAt: now,
        updatedAt: now,
    }
    const result = await studioCollection.insertOne(doc)
    res.status(201).send({ ...doc, _id: result.insertedId })
})

// Ownership is enforced in the query itself + id is cast to ObjectId.
app.put('/api/studios/:id', verifyToken, async (req, res) => {
    const _id = objectId(req.params.id)
    if (!_id) return res.status(400).send({ message: 'Invalid studio id.' })
    const data = parseStudioBody(req.body)

    const result = await studioCollection.updateOne(
        { _id, ownerEmail: req.user.email },
        { $set: { ...data, updatedAt: new Date() } }
    )
    if (result.matchedCount === 0) {
        const exists = await studioCollection.countDocuments({ _id })
        return exists
            ? res.status(403).send({ message: 'You can only edit your own studios.' })
            : res.status(404).send({ message: 'Studio not found.' })
    }
    res.send({ message: 'Studio updated.' })
})

app.delete('/api/studios/:id', verifyToken, async (req, res) => {
    const _id = objectId(req.params.id)
    if (!_id) return res.status(400).send({ message: 'Invalid studio id.' })

    const result = await studioCollection.deleteOne({ _id, ownerEmail: req.user.email })
    if (result.deletedCount === 0) {
        const exists = await studioCollection.countDocuments({ _id })
        return exists
            ? res.status(403).send({ message: 'You can only delete your own studios.' })
            : res.status(404).send({ message: 'Studio not found.' })
    }
    await Promise.all([
        bookingCollection.updateMany({ studioId: _id, status: 'Pending' }, { $set: { status: 'Cancelled', updatedAt: new Date() } }),
        wishlistCollection.deleteMany({ studioId: _id }),
    ])
    res.send({ message: 'Studio deleted.' })
})

// One review per user per studio (re-posting replaces it); rating is recalculated.
app.post('/api/studios/:id/reviews', verifyToken, async (req, res) => {
    const _id = objectId(req.params.id)
    if (!_id) return res.status(400).send({ message: 'Invalid studio id.' })
    const rating = Number(req.body?.rating)
    const comment = String(req.body?.comment ?? '').trim()
    if (!Number.isInteger(rating) || rating < 1 || rating > 5) return res.status(400).send({ message: 'Rating must be between 1 and 5.' })
    if (comment.length < 5) return res.status(400).send({ message: 'Please write a short review (at least 5 characters).' })

    const studio = await studioCollection.findOne({ _id })
    if (!studio) return res.status(404).send({ message: 'Studio not found.' })
    if (studio.ownerEmail === req.user.email) return res.status(403).send({ message: 'You cannot review your own studio.' })

    const reviews = (studio.reviews ?? []).filter((r) => r.userEmail !== req.user.email)
    reviews.unshift({ id: randomUUID(), userEmail: req.user.email, userName: req.user.name, userImage: req.user.image, rating, comment, createdAt: new Date() })
    const avg = reviews.reduce((sum, r) => sum + r.rating, 0) / reviews.length
    await studioCollection.updateOne({ _id }, { $set: { reviews, reviewCount: reviews.length, rating: Math.round(avg * 10) / 10 } })
    res.status(201).send({ message: 'Review added.' })
})

/* ===================== BOOKINGS ===================== */

/**
 * Challenge 2 — double-booking prevention.
 * Ranges [a,b) and [c,d) overlap when a < d AND c < b, so we look for Confirmed bookings
 * on the same studio + date with startMin < newEnd AND endMin > newStart.
 */
function findConflict(studioId, date, startMin, endMin, excludeId) {
    const query = { studioId, date, status: 'Confirmed', startMin: { $lt: endMin }, endMin: { $gt: startMin } }
    if (excludeId) query._id = { $ne: excludeId }
    return bookingCollection.findOne(query)
}
const conflictMessage = (c) => `This time overlaps with a confirmed booking (${c.startTime} - ${c.endTime}) on ${c.date}. Please pick a different slot.`

// Booking creation: the guest is stamped from the token, saved as "Pending".
app.post('/api/bookings', verifyToken, async (req, res) => {
    const { studioId, date, startTime, endTime, notes } = req.body ?? {}
    const _studioId = mustObjectId(studioId, 'studio id')
    if (!/^\d{4}-\d{2}-\d{2}$/.test(String(date))) return res.status(400).send({ message: 'Please choose a valid date.' })
    if (String(date) < new Date().toISOString().slice(0, 10)) return res.status(400).send({ message: 'You cannot book a date in the past.' })

    const startMin = toMinutes(startTime)
    const endMin = toMinutes(endTime)
    if (endMin - startMin < 60) return res.status(400).send({ message: 'Bookings must be at least 1 hour and end after they start.' })

    const studio = await studioCollection.findOne({ _id: _studioId })
    if (!studio) return res.status(404).send({ message: 'Studio not found.' })
    if (studio.ownerEmail === req.user.email) return res.status(403).send({ message: 'You cannot book your own studio.' })

    const conflict = await findConflict(_studioId, String(date), startMin, endMin)
    if (conflict) return res.status(409).send({ message: conflictMessage(conflict) })

    const hours = (endMin - startMin) / 60
    const now = new Date()
    const doc = {
        studioId: _studioId,
        studioTitle: studio.title,
        studioImage: studio.image,
        studioLocation: studio.location,
        hostEmail: studio.ownerEmail,
        hostName: studio.ownerName,
        guestEmail: req.user.email,
        guestName: req.user.name,
        date: String(date),
        startTime: String(startTime),
        endTime: String(endTime),
        startMin,
        endMin,
        hours,
        hourlyRate: studio.hourlyRate,
        securityDeposit: studio.securityDeposit,
        totalPrice: Math.round(hours * studio.hourlyRate * 100) / 100,
        notes: String(notes ?? '').trim().slice(0, 500),
        status: 'Pending',
        createdAt: now,
        updatedAt: now,
    }
    const result = await bookingCollection.insertOne(doc)
    res.status(201).send({ ...doc, _id: result.insertedId })
})

// Reservations I made
app.get('/api/bookings/mine', verifyToken, async (req, res) => {
    const result = await bookingCollection.find({ guestEmail: req.user.email }).sort({ createdAt: -1 }).toArray()
    res.send(result)
})

// Requests for studios I host
app.get('/api/bookings/host', verifyToken, async (req, res) => {
    const result = await bookingCollection.find({ hostEmail: req.user.email }).sort({ createdAt: -1 }).toArray()
    res.send(result)
})

const HOST_TRANSITIONS = { Pending: ['Confirmed', 'Cancelled'], Confirmed: ['Completed', 'Cancelled'] }

app.patch('/api/bookings/:id/status', verifyToken, async (req, res) => {
    const _id = objectId(req.params.id)
    if (!_id) return res.status(400).send({ message: 'Invalid booking id.' })
    const next = String(req.body?.status)

    const booking = await bookingCollection.findOne({ _id })
    if (!booking) return res.status(404).send({ message: 'Booking not found.' })

    const isGuest = booking.guestEmail === req.user.email
    const isHost = booking.hostEmail === req.user.email
    if (!isGuest && !isHost) return res.status(403).send({ message: 'You do not have access to this booking.' })

    if (isGuest && !isHost) {
        if (next !== 'Cancelled' || booking.status !== 'Pending') {
            return res.status(400).send({ message: 'You can only cancel bookings that are still pending.' })
        }
    } else if (!(HOST_TRANSITIONS[booking.status] ?? []).includes(next)) {
        return res.status(400).send({ message: `A ${booking.status.toLowerCase()} booking cannot be changed to ${next.toLowerCase()}.` })
    }

    if (next === 'Confirmed') {
        const conflict = await findConflict(booking.studioId, booking.date, booking.startMin, booking.endMin, _id)
        if (conflict) return res.status(409).send({ message: conflictMessage(conflict) })
    }
    await bookingCollection.updateOne({ _id }, { $set: { status: next, updatedAt: new Date() } })
    res.send({ message: `Booking ${next.toLowerCase()}.`, status: next })
})

/* ===================== WISHLIST + STATS ===================== */

app.get('/api/wishlist', verifyToken, async (req, res) => {
    const saved = await wishlistCollection.find({ userEmail: req.user.email }).sort({ createdAt: -1 }).toArray()
    const result = await studioCollection.find({ _id: { $in: saved.map((s) => s.studioId) } }, NO_REVIEWS).toArray()
    res.send(result)
})

// Toggle: saves the studio if it isn't saved yet, otherwise removes it.
app.post('/api/wishlist/:studioId', verifyToken, async (req, res) => {
    const studioId = objectId(req.params.studioId)
    if (!studioId) return res.status(400).send({ message: 'Invalid studio id.' })

    const removed = await wishlistCollection.deleteOne({ userEmail: req.user.email, studioId })
    if (removed.deletedCount) return res.send({ saved: false })

    if (!(await studioCollection.countDocuments({ _id: studioId }))) return res.status(404).send({ message: 'Studio not found.' })
    await wishlistCollection.insertOne({ userEmail: req.user.email, studioId, createdAt: new Date() })
    res.status(201).send({ saved: true })
})

app.get('/api/stats', verifyToken, async (req, res) => {
    const email = req.user.email
    const [listings, reservations, pendingRequests, saved, earnings] = await Promise.all([
        studioCollection.countDocuments({ ownerEmail: email }),
        bookingCollection.countDocuments({ guestEmail: email }),
        bookingCollection.countDocuments({ hostEmail: email, status: 'Pending' }),
        wishlistCollection.countDocuments({ userEmail: email }),
        bookingCollection.aggregate([
            { $match: { hostEmail: email, status: { $in: ['Confirmed', 'Completed'] } } },
            { $group: { _id: null, total: { $sum: '$totalPrice' } } },
        ]).toArray(),
    ])
    res.send({ listings, reservations, pendingRequests, saved, earnings: earnings[0]?.total ?? 0 })
})

app.get('/', (req, res) => {
    res.send({ message: `Server is running successfully` })
})

app.get('/api/health', (req, res) => {
    res.send({ ok: true, service: 'studiospace-api' })
})

/* ===================== ERRORS ===================== */

app.use((req, res) => res.status(404).send({ message: 'Route not found.' }))

// Express 5 forwards rejected async handlers here, so routes need no try/catch.
app.use((err, req, res, next) => {
    if (err instanceof HttpError) return res.status(err.status).send({ message: err.message })
    console.error(err)
    res.status(500).send({ message: 'Something went wrong on the server.' })
})


/* ===================== START ===================== */

// Locally we listen on a port; on Vercel the exported app runs as a serverless function.
if (!process.env.VERCEL) {
    app.listen(PORT, () => {
        console.log(`Server is running at ${PORT}`)
    })
}

export default app