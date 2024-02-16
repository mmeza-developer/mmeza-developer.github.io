export default function A({children}){
    return <a href={children} className="mdx-p inline-block mb-4 text-xs font-bold capitalize border-b-2 border-orange-600 hover:text-orange-600">{children}</a>
}