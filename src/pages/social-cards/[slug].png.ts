import siteConfig from '~/site.config'
import { Resvg } from '@resvg/resvg-js'
import type { APIContext, InferGetStaticPropsType } from 'astro'
import satori, { type SatoriOptions } from 'satori'
import { html } from 'satori-html'
import { dateString, getSortedPosts } from '~/utils'
import path from 'path'
import fs from 'fs'

// --- SAFE FILE READ + FALLBACKS ---
function safeRead(filePath: string): Buffer | null {
  try {
    if (fs.existsSync(filePath)) {
      return fs.readFileSync(filePath)
    }
  } catch (_) {}
  return null
}

// --- LOAD FONT SAFELY ---
const fontPath = path.resolve(
  './node_modules/@expo-google-fonts/jetbrains-mono/400Regular/JetBrainsMono_400Regular.ttf'
)
const fontData = safeRead(fontPath) ?? Buffer.from([])

// --- LOAD AVATAR SAFELY ---
const avatarPath = path.resolve(siteConfig.socialCardAvatarImage)
const avatarRaw = safeRead(avatarPath)
const avatarBase64 =
  avatarRaw && avatarRaw.length < 600000 // limit ~600 KB
    ? `data:image/jpeg;base64,${avatarRaw.toString('base64')}`
    : null

// --- THEME FALLBACKS ---
const defaultTheme =
  siteConfig.themes.default === 'auto'
    ? siteConfig.themes.include[0]
    : siteConfig.themes.default

const bg = siteConfig.themes.overrides[defaultTheme]?.background ?? '#111111'
const fg = siteConfig.themes.overrides[defaultTheme]?.foreground ?? '#eeeeee'
const accent = siteConfig.themes.overrides[defaultTheme]?.accent ?? '#888888'

const ogOptions: SatoriOptions = {
  fonts: [
    {
      data: fontData,
      name: 'JetBrains Mono',
      style: 'normal',
      weight: 400,
    },
  ],
  height: 630,
  width: 1200,
}

function renderMarkup(title: string, pubDate: string | undefined, author: string) {
  return html(`
  <div tw="flex flex-col max-w-full justify-center h-full bg-[${bg}] text-[${fg}] p-12">
    <div style="border-width: 12px; border-radius: 80px;" tw="flex items-center max-w-full p-8 border-[${accent}]/30">
      ${
        avatarBase64
          ? `<img src="${avatarBase64}" tw="w-1/3 rounded-full border-[${accent}]/30"/>`
          : ''
      }
      <div tw="flex flex-1 flex-col max-w-full justify-center items-center">
        ${
          pubDate
            ? `<p tw="text-3xl max-w-full text-[${accent}]">${pubDate}</p>`
            : ''
        }
        <h1 tw="text-6xl my-14 text-center leading-snug">${title}</h1>
        ${
          author !== title
            ? `<p tw="text-4xl text-[${accent}]">${author}</p>`
            : ''
        }
      </div>
    </div>
  </div>
`)
}

// --- 3 SECOND TIMEOUT WRAPPER ---
async function withTimeout<T>(promise: Promise<T>, ms = 3000): Promise<T> {
  return await Promise.race([
    promise,
    new Promise<T>((_, reject) =>
      setTimeout(() => reject(new Error('timeout')), ms)
    ),
  ])
}

// --- RETURN A BLANK PNG IF IT FAILS ---
const blankPNG = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO2YkdEAAAAASUVORK5CYII=',
  'base64'
)

type Props = InferGetStaticPropsType<typeof getStaticPaths>

export async function GET(context: APIContext) {
  try {
    const { pubDate, title, author } = (context.props as Props) ?? {}

    const safeTitle = title ?? 'Untitled'
    const safeAuthor = author ?? siteConfig.author

    const svg = await withTimeout(
      satori(renderMarkup(safeTitle, pubDate, safeAuthor), ogOptions)
    )

    const png = await withTimeout(
      Promise.resolve(new Resvg(svg).render().asPng())
    )

    return new Response(png, {
      headers: {
        'Content-Type': 'image/png',
        'Cache-Control': 'public, max-age=31536000, immutable',
      },
    })
  } catch (err) {
    // If ANYTHING goes wrong, return blank PNG
    return new Response(blankPNG, {
      headers: {
        'Content-Type': 'image/png',
        'Cache-Control': 'public, max-age=60',
      },
    })
  }
}

export async function getStaticPaths() {
  const posts = await getSortedPosts()

  return [
    ...posts.map((post) => ({
      params: { slug: post.id },
      props: {
        pubDate: post.data.published
          ? dateString(post.data.published)
          : undefined,
        title: post.data.title ?? 'Untitled',
        author: post.data.author ?? siteConfig.author,
      },
    })),
    {
      params: { slug: '__default' },
      props: {
        pubDate: undefined,
        title: siteConfig.title,
        author: siteConfig.author,
      },
    },
  ]
}
