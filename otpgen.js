const formToJSON = (elements, event) =>
  [].reduce.call(
    elements,
    (data, element) => {
      //console.log('formToJSON');  
      //console.log(data);
      //console.log(event);
      //console.log(element);
      //console.log(event.target.getAttribute("order"));
      //console.log(element);
      //console.log("element order :");
      //console.log(element.getAttribute("order"));
      //console.log(event.target.getAttribute("order"));
      //console.log(element.getAttributeNames());
      //if ("id" in element.getAttributeNames()) {
      //  console.log(element.getAttribute("id"));
      //}
      //if (element.order == event.srcElement.
      if (element.getAttribute("order") == event.target.getAttribute("order")) {
        //console.log("data save");
        //console.log(element.name);
        //console.log(element.value);
        //console.log(element.getAttribute("file"));
        data[element.name] = element.name;
	//console.log(element);
	if (element.getAttributeNames().includes('time')) {
          data["time"] = element.getAttribute("time");
	}
	if (element.getAttributeNames().includes('otp')) {
          data["otp"] = element.getAttribute("otp");
	}
	data["file"] = element.getAttribute("file");
	data["order"] = element.getAttribute("order");
      }
      //console.log("data:");
      //console.log(data);
      return data;
    },
    {}
  );
const formPassToJSON = (elements, event) =>
  [].reduce.call(
    elements,
    (data, element) => {
      //console.log('formToJSON');  
      //console.log(data);
      //console.log(event);
      //console.log(element);
      //console.log(event.target.getAttribute("order"));
      //console.log(element);
      //console.log("element order :");
      //console.log(element.getAttribute("order"));
      //console.log(event.target.getAttribute("order"));
      //console.log(element.getAttributeNames());
      //if ("id" in element.getAttributeNames()) {
      //  console.log(element.getAttribute("id"));
      //}
      //if (element.order == event.srcElement.
      //console.log("data save");
      //console.log(element.name);
      //console.log(element.value);
      //console.log(element.getAttribute("file"));
      data[element.name] = element.value;
      //console.log("data:");
      //console.log(data);
      return data;
    },
    {}
  );

const sampleForm = document.querySelector("#sampleForm");
const keypassForm = document.querySelector("#setkeypass");


const handlePassSubmit = (event) => {
  // Stop the form from submitting since were handling that with AJAX.
  event.preventDefault();

  // Call our function to get the form data.
  //console.log(sampleForm.elements);
  const keypass = formPassToJSON(keypassForm.elements, event);

  //console.log("handledata");
  //console.log(data);
  console.log(event);
  submitPassForm(this, keypass);
  
};
document.getElementById('setkeypassbtn').addEventListener('click', handlePassSubmit);

const handleFormSubmit = (event) => {
  // Stop the form from submitting since were handling that with AJAX.
  event.preventDefault();

  // Call our function to get the form data.
  //console.log(sampleForm.elements);
  const data = formToJSON(sampleForm.elements, event);

  //console.log("handledata");
  //console.log(data);
  //console.log(event);
  submitForm(this, data,timeleft,token);
  
};

document.querySelector("#sampleForm");

DIV = document.getElementsByTagName('div')
console.log(DIV);
numOTP = 0;
start=[];
intermediate=[];
for (var div in DIV) {
  //console.log(div);
  try {
    if (DIV[div].getAttribute('name') == "title_otp") {
      numOTP+=1
      //console.log("addeventlisten");
      timeleft=[]
      token=[]
      document.getElementById('btnSubmit_'+ numOTP +'').addEventListener('click', handleFormSubmit,timeleft,token);
    }
  } catch (e) {
    console.log("TypeError: not div")
  }
}
//console.log(numOTP);

/*--Functions--*/
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function submitForm(e, form, timeleft, token) {
    //const btnSubmit = document.getElementById('btnSubmit');
    //btnSubmit.disabled = false;
    //console.log(form);
    delete form[""]
    //console.log(form);
    formstr = JSON.stringify(form)
    //console.log(formstr);
    //const jsonFormData = buildJsonFormData(form, id);
    //console.log(jsonFormData);
    //console.log(form);
    const response = await fetch("/totpgen", { 
    method: 'POST', 
     headers: {
         'Accept': 'application/json',
	 'Content-Type': 'application/json'
    }, 
    body: formstr,
    });
    if (response.ok) { // if HTTP-status is 200-299
      let text = await response.text();
      jsontext = JSON.parse(text.replace(/'/g, '"'));
      timeleft[form["order"]] = jsontext.timeleft;
      token[form["order"]] = jsontext.token;
      //console.log(text);
      //console.log(JSON.stringify(text["timeleft"]));
      //console.log(JSON.stringify(text));
      //console.log(JSON.stringify(text)["timeleft"]);
      //console.log(JSON.parse(JSON.stringify(text)).timeleft);
      //console.log(JSON.parse(text.replace(/'/g, '"')).timeleft);
      //console.log(form["order"]);
      const t = document.getElementById(form["Value_" + form["order"] + "" ]);
      const v = document.getElementById(form["Time_" + form["order"] + "" ]);
      //t.style.fontSize = "100%"
      //t.style.margin = "1px 1px 1px 1px"
      //t.textContent = "";
      await sleep(150);
      t.value = token[form["order"]];
      v.value = timeleft[form["order"]];
      while (timeleft[form["order"]] > 1) {
	  start[form["order"]]=new Date().getTime();
	  //console.log("Update one second");
          //await sleep(1000);
	  await new Promise(r => setTimeout(r, 1000));
	  intermediate[form["order"]]=new Date().getTime();
	  timeleft[form["order"]]=timeleft[form["order"]] - ((intermediate[form["order"]]-start[form["order"]])/1000);
	  //console.log("timeleft");
	  //console.log(form["order"]);
	  //console.log(timeleft[form["order"]]);
          v.value = timeleft[form["order"]];
       }

    } else {
      alert("HTTP-Error: " + response.status);
    }
}

function buildJsonFormData(form) {
    const jsonFormData = { };
    //var rename = new RegExp("^name_" + id + "");
    //var reweight = new RegExp("^weight.*$");
    
    for(const key in form) {
        if (form[key] == "") { 
	  continue;
	}  
        if (rename.test(key)) { 
	  name = form[key];
	  continue
	}
        if (reweight.test(key)) { 
          jsonFormData[name] = Number(form[key]);
	}
    }
    return JSON.stringify(jsonFormData);
}

async function submitPassForm(e, formpass) {
    //const btnSubmit = document.getElementById('btnSubmit');
    //btnSubmit.disabled = false;
    //console.log(form);
    delete formpass[""]
    //console.log(form);
    formpassstr = JSON.stringify(formpass)
    console.log(formpassstr);
    //const jsonFormData = buildJsonFormData(form, id);
    //console.log(jsonFormData);
    //console.log(form);
    const response = await fetch("/totpgpgkey", { 
    method: 'POST', 
     headers: {
         'Accept': 'application/json',
	 'Content-Type': 'application/json'
    }, 
    body: formpassstr,
    });
    if (response.ok) { // if HTTP-status is 200-299
      let text = await response.text();
    } else {
      alert("HTTP-Error: " + response.status);
    }
}
