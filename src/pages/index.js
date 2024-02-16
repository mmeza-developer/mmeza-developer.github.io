import GroupPost from "@/components/group-post";
import SimplePost from "@/components/simple-post";
import { getListOfPosts } from "../utils/postHelper";


export async function getStaticProps() {

  const limit = 6
  const rawPosts = getListOfPosts()
  const sortedPosts = rawPosts.sort(function (a, b) {
    return new Date(b.date) - Date(a.date)
  })

  const posts=JSON.stringify(sortedPosts.slice(0, limit))

  return { props: { posts: posts } }
}

export default function Home({ posts }) {

  const postsList=JSON.parse(posts)

  return (
    <GroupPost>
      {
        postsList.map(post => (
          <SimplePost key={post.slug} data={post}>
          </SimplePost>
        ))

      }
    </GroupPost>
  );
}
