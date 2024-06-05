import { Streamlit } from "streamlit-component-lib"
import "./style.css"

const div = document.body.appendChild(document.createElement("div"))
const button = div.appendChild(document.createElement("button"))
const icon = button.appendChild(document.createElement("span"))
const text = button.appendChild(document.createElement("span"))
icon.className = "icon"
text.textContent = "AUTHORIZE"
button.onclick = async () => {
  // open in popup window
  var left = (screen.width/2)-(popup_width/2);
  var top = (screen.height/2)-(popup_height/2);
  const popup = window.open(authorization_url, "oauthWidget", `toolbar=no, location=no, directories=no, status=no, menubar=no, resizable=no, copyhistory=no,width=${popup_width},height=${popup_height},top=${top},left=${left}`)
  popup.focus()
  // check for popup close
  let qs = await new Promise((resolve, reject) => {
    const interval = setInterval(() => {
      try {
        let redirect_uri = new URLSearchParams(authorization_url).get("redirect_uri")
        let popup_url = (new URL(popup.location.href)).toString()
        let urlParams = new URLSearchParams(popup.location.search)

        // if popup url not redirect_uri, wait for redirect to complete 
        if (!popup_url.startsWith(redirect_uri)) {
          return
        }

        // if popup url is redirect_uri, close popup and return query string
        popup.close()
        clearInterval(interval)
        let result = {}
        for(let pairs of urlParams.entries()) {
          result[pairs[0]] = pairs[1]
        }

        return resolve(result)
      } catch (e) {
        if (e.name === "SecurityError") { 
          // ignore cross-site orign, wait for redirect to complete
          return 
        }
        return reject(e)
      }
    }, 1000)
  })
  // send code to streamlit
  Streamlit.setComponentValue(qs)
}

let authorization_url
let popup_height
let popup_width

function onRender(event) {
  const data = event.detail
  authorization_url = data.args["authorization_url"]
  popup_height = data.args["popup_height"]
  popup_width = data.args["popup_width"]
  text.textContent =  data.args["name"]
  if(data.args["icon"]) {
    icon.style.backgroundImage = `url("${data.args["icon"]}")`
  } else {
    icon.style.width = "0px"
    icon.style.height = "0px"
  }
  
  if(data.args["use_container_width"]) {
    button.style.width = "100%"
  }

  if(data.args["auto_click"] && !window.opener && !window.clicked) {
    button.click()
    window.clicked = true
  }

  console.log(`authorization_url: ${authorization_url}`)
  Streamlit.setFrameHeight()
}

Streamlit.events.addEventListener(Streamlit.RENDER_EVENT, onRender)
Streamlit.setComponentReady()