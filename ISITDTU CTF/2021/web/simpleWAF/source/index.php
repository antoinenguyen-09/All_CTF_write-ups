This is a simple XSS challenge, if you can steal cookie, bot will check it at <a href=bot.php>here</a>: 
<br>
<code><span style="color: #000000">
This&nbsp;is&nbsp;a&nbsp;simple&nbsp;XSS&nbsp;challenge,&nbsp;if&nbsp;you&nbsp;can&nbsp;steal&nbsp;cookie,&nbsp;bot&nbsp;will&nbsp;check&nbsp;it&nbsp;at&nbsp;&lt;a&nbsp;href=bot.php&gt;here&lt;/a&gt;:&nbsp;<br />&lt;br&gt;<br /><span style="color: #0000BB">&lt;?php&nbsp;<br /><br />show_source</span><span style="color: #007700">(</span><span style="color: #0000BB">__FILE__</span><span style="color: #007700">);<br /></span><span style="color: #0000BB">$xss&nbsp;</span><span style="color: #007700">=&nbsp;</span><span style="color: #0000BB">$_GET</span><span style="color: #007700">[</span><span style="color: #DD0000">'xss'</span><span style="color: #007700">];<br /><br /></span><span style="color: #0000BB">$tmpxss&nbsp;</span><span style="color: #007700">=&nbsp;</span><span style="color: #0000BB">$xss</span><span style="color: #007700">;<br />do<br />{<br />&nbsp;&nbsp;&nbsp;&nbsp;</span><span style="color: #0000BB">$xss&nbsp;</span><span style="color: #007700">=&nbsp;</span><span style="color: #0000BB">$tmpxss</span><span style="color: #007700">;<br />&nbsp;&nbsp;&nbsp;&nbsp;</span><span style="color: #0000BB">$tmpxss&nbsp;</span><span style="color: #007700">=&nbsp;</span><span style="color: #0000BB">urldecode</span><span style="color: #007700">(</span><span style="color: #0000BB">$xss</span><span style="color: #007700">);<br />}&nbsp;while(</span><span style="color: #0000BB">$tmpxss&nbsp;</span><span style="color: #007700">!=&nbsp;</span><span style="color: #0000BB">$xss</span><span style="color: #007700">);<br /><br /></span><span style="color: #0000BB">$xss&nbsp;</span><span style="color: #007700">=&nbsp;</span><span style="color: #0000BB">html_entity_decode</span><span style="color: #007700">(</span><span style="color: #0000BB">$xss</span><span style="color: #007700">);<br /><br /></span><span style="color: #0000BB">$valid&nbsp;</span><span style="color: #007700">=&nbsp;</span><span style="color: #0000BB">true</span><span style="color: #007700">;<br />if(</span><span style="color: #0000BB">preg_match</span><span style="color: #007700">(</span><span style="color: #DD0000">"/\&lt;\w+.*on\w+=.*/i"</span><span style="color: #007700">,&nbsp;</span><span style="color: #0000BB">$xss</span><span style="color: #007700">))<br />{<br />&nbsp;&nbsp;&nbsp;&nbsp;</span><span style="color: #0000BB">$valid&nbsp;</span><span style="color: #007700">=&nbsp;</span><span style="color: #0000BB">false</span><span style="color: #007700">;<br />}<br /><br />if(</span><span style="color: #0000BB">preg_match</span><span style="color: #007700">(</span><span style="color: #DD0000">"/\&lt;\w+.*src=.*/i"</span><span style="color: #007700">,&nbsp;</span><span style="color: #0000BB">$xss</span><span style="color: #007700">))<br />{<br />&nbsp;&nbsp;&nbsp;&nbsp;</span><span style="color: #0000BB">$valid&nbsp;</span><span style="color: #007700">=&nbsp;</span><span style="color: #0000BB">false</span><span style="color: #007700">;<br />}<br /><br />if(</span><span style="color: #0000BB">preg_match</span><span style="color: #007700">(</span><span style="color: #DD0000">"/\&lt;\w+.*href=.*/i"</span><span style="color: #007700">,&nbsp;</span><span style="color: #0000BB">$xss</span><span style="color: #007700">))<br />{<br />&nbsp;&nbsp;&nbsp;&nbsp;</span><span style="color: #0000BB">$valid&nbsp;</span><span style="color: #007700">=&nbsp;</span><span style="color: #0000BB">false</span><span style="color: #007700">;<br />}<br /><br />if(</span><span style="color: #0000BB">preg_match</span><span style="color: #007700">(</span><span style="color: #DD0000">"/\&lt;script.*/i"</span><span style="color: #007700">,&nbsp;</span><span style="color: #0000BB">$xss</span><span style="color: #007700">))<br />{<br />&nbsp;&nbsp;&nbsp;&nbsp;</span><span style="color: #0000BB">$valid&nbsp;</span><span style="color: #007700">=&nbsp;</span><span style="color: #0000BB">false</span><span style="color: #007700">;<br />}<br /><br />if(</span><span style="color: #0000BB">preg_match</span><span style="color: #007700">(</span><span style="color: #DD0000">"/\&lt;object.*/i"</span><span style="color: #007700">,&nbsp;</span><span style="color: #0000BB">$xss</span><span style="color: #007700">))<br />{<br />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span><span style="color: #0000BB">$valid&nbsp;</span><span style="color: #007700">=&nbsp;</span><span style="color: #0000BB">false</span><span style="color: #007700">;<br />}<br /><br />if(</span><span style="color: #0000BB">$valid&nbsp;</span><span style="color: #007700">==&nbsp;</span><span style="color: #0000BB">true</span><span style="color: #007700">)<br />{<br />&nbsp;&nbsp;&nbsp;&nbsp;echo&nbsp;</span><span style="color: #0000BB">$xss</span><span style="color: #007700">;<br />}<br />else<br />{<br />&nbsp;&nbsp;&nbsp;&nbsp;echo&nbsp;</span><span style="color: #DD0000">"WAF&nbsp;block"</span><span style="color: #007700">;<br />}<br /><br /></span><span style="color: #0000BB">?&gt;<br /></span>
</span>
</code>

<?php 

show_source(__FILE__);
$xss = $_GET['xss'];

$tmpxss = $xss;
do
{
    $xss = $tmpxss;
    $tmpxss = urldecode($xss);
} while($tmpxss != $xss);

$xss = html_entity_decode($xss);

$valid = true;
if(preg_match("/\<\w+.*on\w+=.*/i", $xss))
{
    $valid = false;
}

if(preg_match("/\<\w+.*src=.*/i", $xss))
{
    $valid = false;
}

if(preg_match("/\<\w+.*href=.*/i", $xss))
{
    $valid = false;
}

if(preg_match("/\<script.*/i", $xss))
{
    $valid = false;
}

if(preg_match("/\<object.*/i", $xss))
{
        $valid = false;
}

if($valid == true)
{
    echo $xss;
}
else
{
    echo "WAF block";
}
?>
