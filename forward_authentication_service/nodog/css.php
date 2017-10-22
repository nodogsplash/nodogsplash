body {
background-color:lightgrey;
color:black;
font-family: Arial, 'Arial Black', sans-serif;
}

input[type=text], input[type=email], input[type=password] {
margin-left: 0%; margin-right: 0%;
text-align:left;   
display: left;
font-size: 1em;
line-height: 1em;
color: #333;
font-weight: bold;
height: 1.5em;
width: auto;
max-width: 100%;
border: 1px solid #bbb;
}

input[type=submit], input[type=button], input[type=file], button[type=link], select[type=list] {
-webkit-appearance: none;
-moz-appearance: none;
margin-left: 0%;
margin-right: 5%;
text-align:left;   
display: left;
font-size: 1em;
line-height: 1em;
color: #333;
font-weight: bold;
height: 1.5em;
width: auto;
max-width: 95%;
background: #fdfdfd;
background: -moz-linear-gradient(top, #fdfdfd 0%, #bebebe 100%); 
background: -webkit-gradient(linear, left top, left bottom, color-stop(0%,#fdfdfd), color-stop(100%,#bebebe));
background: -webkit-linear-gradient(top, #fdfdfd 0%,#bebebe 100%);
background: -o-linear-gradient(top, #fdfdfd 0%,#bebebe 100%);
background: -ms-linear-gradient(top, #fdfdfd 0%,#bebebe 100%);
background: linear-gradient(to bottom, #fdfdfd 0%,#bebebe 100%);
border: 1px solid #bbb;
border-radius: 10px;
-webkit-border-radius: 10px;
-moz-border-radius: 10px;
}

.box
{
border: 2px solid #aaa;
border-radius: 4px;
padding: 5px;
min-width:200px;
max-width:100%;
}

@media screen and (min-width: 500px)  {
.box {max-width:50%;}
}

textarea
{
width: 97%;
margin-left:0%;
margin-right:0%;
}

img
{
width: 100%;
margin-left:0%;
margin-right:0%;
}

mark {
background-color:red;
color:white;
}

hr {
display:block;
margin-top:0.5em;
margin-bottom:0.5em;
margin-left:auto;
margin-right:auto;
border-style:inset;
border-width:5px;
} 

.offset {
max-width:400px;
min-width:200px;
margin: auto;

}

@media screen and (min-width: 2500px)  {
body {font-size: 2em;}
}


