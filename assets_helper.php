<?php
if (!function_exists('requireToVarInit')) {
	function requireToVarInit($file = null, $args = []){
		ob_start();
		extract($args);
		// die($file);
		if($file){  
			require($file);
			return ob_get_clean();
		}
	}
}

if (!function_exists('filterResultCss')) {
	function filterResultCss($jsStr) {
		//$jsStr = preg_replace('~[^"\'\(]// ([^\r\n]*)[^"\'\)]~', '/*$1 */', $jsStr);
		$jsStr = str_replace("/(?:(?:\/\*(?:[^*]|(?:\*+[^*\/]))*\*+\/)|(?:(?<!\:|\\\|\')\/\/.*))/", "", $jsStr);
		$jsStr = preg_replace( '~//<!\[CDATA\[\s*|\s*//\]\]>~' , '', $jsStr);
		$jsStr = preg_replace( '/(?:(?:\/\*(?:[^*]|(?:\*+[^*\/]))*\*+\/)|(?:(?<!\:|\\\)\/\/[^"\'].*))/' , '', $jsStr);
		$jsStr = str_replace("\r", " ", $jsStr);
		$jsStr = str_replace("\n", "", $jsStr);
		$jsStr = str_replace("\t", "", $jsStr);
		$jsStr = str_replace(" = ", "=", $jsStr);
		$jsStr = str_replace(") {", "){", $jsStr);
		$jsStr = str_replace(" ( ", "(", $jsStr);
		$jsStr = str_replace(" ) ", ")", $jsStr);
		$jsStr = str_replace("; ", ";", $jsStr);
		$jsStr = str_replace("if ", "if", $jsStr);
		$jsStr = str_replace("for ", "for", $jsStr);
		$jsStr = str_replace(" >= ", ">=", $jsStr);
		$jsStr = str_replace(" + ", "+", $jsStr);
		$jsStr = str_replace(" - ", "-", $jsStr);
		$jsStr = str_replace(" * ", "*", $jsStr);
		$jsStr = str_replace(" / ", "/", $jsStr);
		$jsStr = str_replace(" || ", "||", $jsStr);
		$jsStr = str_replace(" && ", "&&", $jsStr);
		$jsStr = str_replace("try ", "try", $jsStr);
		$jsStr = str_replace(", ", ",", $jsStr);
		$jsStr = str_replace(" == ", "==", $jsStr);
		$jsStr = str_replace(" != ", "!=", $jsStr);
		$jsStr = str_replace(": ", ":", $jsStr);
		$jsStr = str_replace("  ", "", $jsStr);
		$jsStr = str_replace("   ", "", $jsStr);
		$jsStr = str_replace("    ", "", $jsStr);
		return $jsStr;
	}

}