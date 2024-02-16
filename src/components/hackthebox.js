function colorDificultad(dif) {
    if (dif === "Insane") {
        return " text-red-900"
    } else if (dif === "Hard") {
        return " text-red-500"
    } else if (dif === "Medium") {
        return "text-orange-400"
    } else if (dif === "Easy") {
        return " text-green-400"
    }
}

function isHackTheBoxPost(data) {

    return data.tags.indexOf("HackTheBox") != -1
}

export default function HackTheBox({metadata}) {
    return (<div>
        {
            isHackTheBoxPost(metadata) && (
                <div>
                    <h6 className="text-center pt-3">Dificultad: <span className={colorDificultad(metadata.dificultad)}>{metadata.dificultad}</span></h6>
                    <h6 className="text-center ">OS {metadata.os}</h6>
                </div>
            )

        }


    </div>)
}