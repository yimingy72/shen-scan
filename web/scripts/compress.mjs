import { readdir, readFile, writeFile } from 'node:fs/promises'
import { gzipSync } from 'node:zlib'

// Compress once at build time; serving the UI should not spend CPU compressing it.
for (const name of await readdir('dist/assets')) {
  if (!/\.(js|css|svg|json)$/.test(name)) continue
  const file = `dist/assets/${name}`
  await writeFile(`${file}.gz`, gzipSync(await readFile(file), { level: 9 }))
}
