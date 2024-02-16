import Link from 'next/link'
 
export default function NotFound() {
     return (
        <div className="bg-white">
            <div className="w-9/12 m-auto py-1 min-h-screen flex items-center justify-center">
                
                    <div className="border border-orange-400 text-center p-8">
                        <h1 className="text-9xl font-bold text-orange-600">404</h1>
                        <h1 className="text-6xl text-black font-medium py-8">Ups! Algo extraño sucedió</h1>
                        <p className="text-3xl  text-black pb-8 px-12 font-medium">La página que buscas no existe :(</p>
                        <Link href="/" className="bg-gradient-to-b from-black to-gray-900 hover:from-orange-500 hover:to-orange-300 text-white font-semibold px-6 py-3 rounded-md mr-6">
                            Home
                        </Link>
                       
                    </div>
                
            </div>
        </div>
    )
}