import path from 'path'
import fs from 'fs'
import matter from 'gray-matter'

export const getListOfPosts = () => {

  try {
    const folder = path.join(process.cwd(), 'docs')
    const files = fs.readdirSync(folder)
    const mdFiles = files.filter(file => file.endsWith('.md'))

    return mdFiles.map(filename => {
      const contents = fs.readFileSync(path.join(folder, filename), 'utf8')
      const { data } = matter(contents)

      return {
        ...data,
        slug: filename.replace('.md', '')
      }
    })

  } catch (e) {
    console.log(e)
  }
}

export const getPostContent = (slug) => {
  try {
    const file = path.join(process.cwd(), 'docs', slug) + '.md'
    const content = fs.readFileSync(file, 'utf8')
    return matter(content)
  } catch (e) {
      console.log(e)
  }

}