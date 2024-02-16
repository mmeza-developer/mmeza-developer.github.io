import Image from 'next/image'

const basePath=""

export default function ImageBlog({ src, alt }) {

  const imgStyle = {
    'width': 'auto',
    'height': 'auto',
    'marginLeft': 'auto',
    'marginRight': 'auto',
  }

  return (

      <Image src={`${basePath}${src}`} alt={alt} sizes="50vw"
        style={imgStyle}
        width={400}
        height={200} />


  )


}