export default function A({href,children}){
    return <a href={href} className="mdx-p inline-block mb-4 text-xs font-bold capitalize md:border-b-2 md:border-orange-600 hover:text-orange-600">{children}</a>
}