import Link from 'next/link'


function tagLink(tags){

    if (tags.indexOf("Development") != -1) {
        return "/dev"
    }else if(tags.indexOf("HackTheBox") != -1){
        return "/htb"
    }else if(tags.indexOf("Pentesting Web") != -1){
        return "/pentesting-web"
    }
}

export default function SimplePost({ data }) {
    return (

        <div className="w-full max-w-full mb-8 sm:w-1/2 px-4 lg:w-1/3 flex flex-col">

            <div className="object-cover object-center w-full border min-h-32 border-e-gray-300 border-s-gray-300 border-t-gray-300 bg-white p-5" >
                <Link
                    href={`posts/post/${data.slug}`}
                    className="block mb-4 text-2xl font-black leading-tight hover:underline hover:text-orange-600"
                >
                    {data.title}
                </Link>
            </div>

            <div className="flex flex-grow">
                <div className="triangle"></div>
                <div className="flex flex-col justify-between px-4 py-6 bg-white border border-gray-300 text">
                    <div>
                        <Link href={`${tagLink(data.tags)}`} className="inline-block mb-4 text-xs font-bold capitalize border-b-2 border-orange-600 hover:text-orange-600">
                            {data.tags}
                        </Link>

                        <p className="mb-4">
                        <Link href={`posts/post/${data.slug}`} className="mb-4 text-xs   hover:text-orange-600">
                            {`${data.subtitle.slice(0, 150)} ...`}
                            </Link>
                        </p>
                    </div>
                    <div>
                        <Link href={`posts/post/${data.slug}`} className="inline-block pb-1 mt-2  text-base font-black  text-orange-600 uppercase border-b border-transparent hover:border-orange-600">Leer -&gt;</Link>
                    </div>
                </div>
            </div>


        </div>


    )
}