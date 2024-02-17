import Link from 'next/link'

export default function GroupPost({children}) {
    return (
        <div className="flex-grow text-gray-900 bg-gray-100 ">
            <section className="flex flex-col justify-center  max-w-6xl px-2 py-10 mx-auto ">
                <div className="flex flex-wrap items-center justify-between mb-4">
                    <h2 className="mr-10 sm:text-sm sm:text-center text-xl font-bold  leading-none md:text-xl">
                        Últimas publicaciones
                    </h2>
                    <Link href={`posts`} className="block sm:text-sm pb-1 mt-2 font-bold text-black  border-b border-transparent hover:border-orange-600  hover:text-orange-600">
          Ver todas las publicaciones -&gt;
                    </Link>
                    
                </div>
                <div className="flex flex-wrap mx-4">
                {children}
                </div>
            </section>
        </div>
    )
}