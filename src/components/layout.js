import Navbar from './nav'
import Footer from './footer'
 
export default function Layout({ children }) {
  return (
    <div className='flex flex-col h-screen'>
      <Navbar />
      <main className='flex-grow'>{children}</main>
      <Footer />
    </div>
  )
}