import { getListOfPosts, getPostContent } from "@/utils/postHelper"
import Markdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import H1 from '@/components/title'
import H2 from "@/components/subtitle"
import H3 from "@/components/sub-subtitle"
import A from "@/components/link"
import ImageBlog from "@/components/image"
import P from "@/components/paragraph"
import Code from "@/components/code"
import Pre from "@/components/pre"
import UL from "@/components/ul"
import LI from "@/components/li"
import HackTheBox from "@/components/hackthebox"
import Blockquote from "@/components/citas"


export async function getStaticPaths() {

  const posts = getListOfPosts()

  const listPost = posts.map(post => { 
    return {params: { slug: post.slug } }
  })

  return {
    paths: listPost,
    fallback: false, // false or "blocking"
  }
}

export async function getStaticProps({ params }) {
  const markdownContent = getPostContent(params.slug)

  const content= JSON.stringify(markdownContent)


  
  return { props: { markdownData: content } }
}

function dateFormat(dateString) {
  const date=new Date(dateString)
  return date.toLocaleDateString('es-ES', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  })
}

export default function Page({ markdownData }) {

  const {content, data}=JSON.parse(markdownData)
  
  return (
    <div className="">
      <div className="sm:mx-5 md:mx-44">
      <h1 className="text-6xl sm:text-3xl text-center py-20 font-bold">{data.title}</h1>
      <h5 className=" text-xl sm:text-md text-center">{data.subtitle}</h5>
      <HackTheBox metadata={data}></HackTheBox>

      <h6 className="text-center py-5">Publicado el {dateFormat(data.date)}</h6>

      <Markdown remarkPlugins={[remarkGfm]} components={{
        h1: H1,
        h2: H2,
        h3: H3,
        p: P,
        a: A,
        code: Code,
        pre: Pre,
        img: ImageBlog,
        ul: UL,
        li: LI,
        blockquote: Blockquote,
      }}>
        {content}
      </Markdown>
      </div>
    </div>

  )
}