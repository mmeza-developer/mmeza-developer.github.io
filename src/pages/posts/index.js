import SimplePost from "@/components/simple-post"
import GroupPost from "@/components/group-post"
import { getListOfPosts } from '../../utils/postHelper'

export async function getStaticProps() {

    const rawPosts = getListOfPosts()
    const posts=JSON.stringify(rawPosts)
  
    return { props: { posts: posts } }

  }

export default function Page({posts}) {
    const postsList = JSON.parse(posts)
    return (
        <GroupPost>
            {
                postsList.map(post => (
                    <SimplePost key={post.slug} data={post}>
                    </SimplePost>
                ))

            }
        </GroupPost>
        )
}