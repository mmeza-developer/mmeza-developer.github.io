import Link from 'next/link'

export default function NavBar(){
    return (
      <div className="w-full  bg-black">
        <div className="max-w-screen-xl mx-auto">

        <header className="flex items-center justify-between py-5  ">
          <Link href="/" className="px-2 text-xl lg:px-0 font-bold text-orange-400">
            Github Blog
          </Link>

          <ul className="inline-flex items-center">
            <li className="px-2 md:px-4">
              <Link href="/" className="text-white font-semibold hover:text-orange-500"> Home </Link>
            </li>
            <li className="px-2 md:px-4">
              <Link href="/dev" className="text-white font-semibold hover:text-orange-500"> Developerment </Link>
            </li>
            <li className="px-2 md:px-4">
              <Link href="/htb" className="text-white font-semibold hover:text-orange-500"> HackTheBox </Link>
            </li>
            <li className="px-2 md:px-4">
              <Link href="/pentesting-web" className="text-white font-semibold hover:text-orange-500"> Pentesting Web </Link>
            </li>
          
          </ul>

        </header>
      </div>
      </div>
    )
} 