import Link from 'next/link'
import { useState } from 'react'



export default function NavBar() {
 
  let [open,setOpen]=useState(false)

  const openMenu=(e)=>{
    setOpen(!open)
  }

  return (
    <div className="w-full  bg-black">
      <div className="max-w-screen-xl mx-auto">

        <header className="flex mx-20 sm:mx-5 items-center justify-between py-5  ">
          <Link href="/" className="px-2 text-xl lg:px-0 font-bold text-orange-400">
            Github Blog
          </Link>

          <ul className="inline-flex items-center">

            <li className="px-2 md:px-4 sm:hidden ">
              <Link href="/" className="text-white font-semibold hover:text-orange-500"> Home </Link>
            </li>
            <li className="px-2 md:px-4 sm:hidden  ">
              <Link href="/dev" className="text-white font-semibold hover:text-orange-500"> Developerment </Link>
            </li>
            <li className="px-2 md:px-4 sm:hidden ">
              <Link href="/htb" className="text-white font-semibold hover:text-orange-500"> HackTheBox </Link>
            </li>
            <li className="px-2 md:px-4 sm:hidden ">
              <Link href="/pentesting-web" className="text-white font-semibold hover:text-orange-500"> Pentesting Web </Link>
            </li>

            <li className="p-2 md:px-4 md:hidden ">
              <div  className="text-whitefont-semibold hover:text-orange-500">
                <span onClick={() => { setOpen(!open) }}  className='navbar-burger'>
                  <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6 text-gray-100 hover:text-orange-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16" />
                  </svg>
                </span>
              </div>
            </li>

          </ul>

          <div onMouseLeave={() => { setOpen(false)}} className={`${open ? "block" : "sm:hidden"} md:hidden mr-2 absolute right-0 mt-52 w-48 bg-black border-2 border-gray-300 rounded-md overflow-hidden shadow-xl z-20`}>
            <Link onClick={ openMenu} href="/" class="block text-center px-6 py-2 bg-black text-sm text-white border-b hover:text-orange-500">Home </Link>
            <Link onClick={openMenu} href="/dev" class="block text-center px-6 py-2 bg-black text-sm text-white border-b hover:text-orange-500">Development </Link>
            <Link onClick={openMenu} href="/htb" class="block text-center px-4 py-2 bg-black text-sm text-white border-b hover:text-orange-500">HackTheBox </Link>
            <Link onClick={openMenu} href="/pentesting-web" class="block text-center px-4 py-2 bg-black text-sm text-white border-b hover:text-orange-500">Pentesting Web</Link>
          </div>


        </header>
      </div>
    </div>
  )
} 