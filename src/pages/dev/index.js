import SimplePost from "@/components/simple-post";
import GroupPost from "@/components/group-post";
import { getListOfPosts } from "@/utils/postHelper";


export async function getStaticProps() {

    const rawPosts = getListOfPosts()
    const posts = JSON.stringify(rawPosts)

    return { props: { posts: posts } }
}

export default function Home({ posts }) {

    const postsArray=JSON.parse(posts)

    const postsList = postsArray.filter((post) => {
        if (post.tags.indexOf("Development") != -1) {
            return post
        }
    })
    return (
        <main >

            <GroupPost>
                {
                    postsList.map(post => (
                        <SimplePost key={post.slug} data={post}>
                        </SimplePost>
                    ))

                }
            </GroupPost>

        </main>
    );
}
