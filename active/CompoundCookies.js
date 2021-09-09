/**
 * Input Vector script to help Zap attack compound cookies, i.e. cookies that contain multiple parameters
 * Format of a Compound cookie is Classic ASP compliant, i.e. of the form:
 *        <compoundcookie>=<p1name>=<p1value>&<p2name>=<p2value>&...
 * where parameter names and values must be URI component encoded. Generates parameters in the form:
 *        <compoundcookie>:<p1name>=<p1value>
 *        <compoundcookie>:<p2name>=<p2value>
 *        ...
 * These compound cookies should be filtered out in Active Scan Exclude Param to stop ZAP attacking these cookies directly.
 */
var ScriptVars    = Java.type('org.zaproxy.zap.extension.script.ScriptVars');
var HtmlParameter = Java.type('org.parosproxy.paros.network.HtmlParameter');
var COOKIE_TYPE   = org.parosproxy.paros.network.HtmlParameter.Type.cookie;

/* List of compound cookies to target - either burn in list below (i.e. ccList = [ "<compoundcookie1>", "<compoundcookie2>", ... ]; )
 * or set via 'CompoundCookies' global var as a '&' separated list (i.e. "<compoundcookie1>&<compoundcookie2>&..." ) */
var ccList = [ ];

function parseParameters(helper, msg)
{
  var headers = msg.getRequestHeader();
  var cookies = headers.getCookieParams();
  var ix, ei, pi, pl;
  if(ccList.length == 0)
  {
    if((ei = ScriptVars.getGlobalVar('CompoundCookies')).equals('') || ((ccList = ei.split('&')).length == 0))
    {
      print('CompoundCookie Setup Error: GlobalVar CompoundCookies must be set to \'&\' separated list of compound cookies');
      return;
    }
    //print('CompoundCookie list: ' + ccList);
  }
  //print('parseParameters: ' + msg.getRequestHeader().getURI().toString());
  for(var ci = cookies.iterator(); ci.hasNext(); )
  {
    var cc = ci.next();
    if((ix = ccList.indexOf(cc.getName())) >= 0)
    {
      pl = cc.getValue().split('&');
      //print("  Splitting: " + ccList[ix]);
      for(pi=0; pi < pl.length; pi++) {
        if((ei=pl[pi].indexOf('=')) > 0) {
          //print("    Var " + decodeURIComponent(pl[pi].substring(0,ei)) + "=" + decodeURIComponent(pl[pi].substring(ei+1)));
          helper.addParamQuery(ccList[ix]+':'+decodeURIComponent(pl[pi].substring(0,ei)),decodeURIComponent(pl[pi].substring(ei+1)));
        }
      }
    }
  }
}

/* Only one parameter is changed at a time so only one compound cookie to update */
function setParameter(helper, msg, param, value, escaped)
{
  var size = helper.getParamNumber();
  var pos = helper.getCurrentParam().getPosition();
  var ii,di,pn,cn,pf,vv;
  if((pos < size) && ((di = (pn = helper.getParamName(pos)).indexOf(':')) > 0) &&
     (ccList.indexOf((cn = pn.substring(0,di))) >= 0))
  {
    var headers = msg.getRequestHeader();
    var cookies = headers.getCookieParams();
    pf = cn + ':';
    vv = '';
    for(ii=0; ii<size; ii++) {
      if(ii == pos) {
        vv = encodeURIComponent(helper.getParamName(ii).slice(di+1)) + "=" + encodeURIComponent(value) + "&" + vv;
      }
      else if((pn = helper.getParamName(ii)).startsWith(pf))
      {
        vv = encodeURIComponent(pn.slice(di+1)) + "=" + encodeURIComponent(helper.getParamValue(ii)) + "&" + vv;
      }
    }
    /* remove trailing '&' */
    vv = vv.slice(0,-1);
    //print('SetParameter: ' + cn + '=' + vv);
    vv = new HtmlParameter(COOKIE_TYPE,cn,vv);
    for(var ci = cookies.iterator(); ci.hasNext(); ) {
      var cc = ci.next();
      if (cc.getName().equals(cn)) {
        ci.remove();
        break;
      }
    }
    cookies.add(vv);
    msg.getRequestHeader().setCookieParams(cookies);
  }
  else {
    print('CompoundCookie SetParameter Error: Invalid input ' + size + ', ' + pos + ' -> ' + pn);
  }
}


/* Return null to Use default method */
function getLeafName(helper, nodeName, msg) {
	return null;
}

/* Return null to Use default method */
function getTreePath(helper, msg) {
	return null;
}
