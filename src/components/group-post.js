import Link from 'next/link'

export default function GroupPost({children}) {
    return (
        <div className="flex-grow text-gray-900 bg-gray-100 ">
            <section className="flex flex-col justify-center  max-w-6xl px-2 py-10 mx-auto sm:px-10">
                <div className="flex flex-wrap items-center justify-between mb-4">
                    <h2 className="mr-10 text-xl font-bold  uppercase leading-none md:text-xl">
                        Ultimas publicaciones
                    </h2>
                    <Link href={`posts`} className="block pb-1 mt-2 text-base font-black text-black-600  border-b border-transparent hover:border-orange-600  hover:text-orange-600">
          Ver todas las publicaciones -&gt;
                    </Link>
                    
                </div>
                <div className="flex flex-wrap  mx-4">
                {children}
                </div>
            </section>
        </div>
    )
}