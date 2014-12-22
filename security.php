<?php
if (! defined ( 'ENVIRONMENT' ))
	exit ( 'Direct script access is forbidden.' );

/**
 * Security.php
 *
 * A biztonságért felelős metódusok vannak itt összegyűjtve
 *
 * LICENSE: Licensz információk
 *
 * @category CMS
 * @package CMS_blog
 * @subpackage Helpers
 * @version 1.0.0
 * @author Papp Krisztián
 * @since File available since Release 1.0.0
 *       
 */
class PIE_Security {
	function __construct() {
		Security_Config::init ();
	}
	
	/**
	 * Validates a string
	 *
	 * @param
	 *        	string
	 * @return s boolean
	 *        
	 */
	static function isvalid($string) {
		// Végigjárjuk a nem engedélyezett karakterek tömbjét
		foreach ( Security_Config::$donotallowstrings as $needle ) {
			// Ellenőrízzük, hogy megvan-e az átadott stringben az, ha igen, FALSE-al térünk vissza
			if (strpos ( strtolower ( $string ), $needle ) != FALSE)
				return FALSE;
		}
		// Visszatérünk TRUE-val
		return TRUE;
	}
	
	/**
	 * Sanitize the string from malicious content
	 * 
	 * @param
	 *        	string
	 * @return string
	 *
	 */
	static function sanitizeString($string) {
		// Végigjárjuk a nem engedélyezett karakter(láncokat) tartalmazó tömböt
		foreach ( Security_Config::$donotallowstrings as $badstrings ) {
			// Lecsapjuk az üres szóközöket, utána kikapcsoljuk a HTML karaktereket, végül kiszedjük nem kívánatos stringeket
			$string = str_replace ( $badstrings, '', $string );
		}
		$string = htmlspecialchars ( trim ( $string ) );
		// Visszaadjuk az átalakított stringünket.
		return $string;
	}
	/**
	 * Creates a captcha
	 * 
	 * @return string
	 * @uses GD
	 * @todo Draw attention of the customers that it NEEDS the GD library
	 */
	static function Captcha() {
		$str = '';
		$im = imagecreate ( 150, 40 );
		
		$feher = imagecolorallocate ( $im, rand ( 150, 255 ), rand ( 150, 255 ), rand ( 150, 255 ) );
		$fekete = imagecolorallocate ( $im, rand ( 0, 100 ), rand ( 0, 100 ), rand ( 0, 100 ) );
		$szurke = imagecolorallocate ( $im, rand ( 100, 150 ), rand ( 100, 150 ), rand ( 100, 150 ) );
		$chars = 'abcdefghijklmnopqrstxyzABCDEFGHJKLMNPQRSTXYZ23456789';
		for($no = 0; $no < 6; $no ++) {
			$str .= $chars [rand ( 0, strlen ( $chars ) - 1 )];
		}
		imagefill ( $im, 0, 0, $feher );
		imagettftext ( $im, 20, 0, 12, 32, $szurke, CSSPATH . "4.ttf", $str );
		imagettftext ( $im, 20, 0, 10, 30, $fekete, CSSPATH . "4.ttf", $str );
		imagejpeg ( $im, CSSPATH . 'captcha.jpg' );
		return $str;
	}
	
	// Cookie protection section //
	// ************************** //
	
	/**
	 * Signs a cookie
	 * 
	 * @param string $key        	
	 * @param string $value        	
	 * @param int $time        	
	 * @return void
	 *
	 */
	public static function registerCookie($key, $value, $time) {
		$value = $value . '--' . md5 ( $value . Security_Config::$salt );
		setcookie ( $key, $value, $time, '/' );
		return;
	}
	/**
	 * Loops through our cookie superglobal and destroys anything but the signed cookies
	 * 
	 * @return void
	 * @todo the session cookie should be created via our registerCookie method
	 */
	public static function validateCookies() {
		foreach ( $_COOKIE as $key => $value ) {
			// Skip our session cookie which isn't created via our cookie functions
			if ($key != session_name ()) {
				$parts = explode ( '--', $value );
				if (! isset ( $parts [1] ) or $parts [1] != md5 ( $parts [0] . Security_Config::$salt )) {
					self::destroyCookie ( $key );
				}
			}
		}
		return;
	}
	/**
	 * Gets the value from a signed cookie
	 * 
	 * @return string or FALSE
	 */
	public static function getCookie($key) {
		if (isset ( $_COOKIE [$key] )) {
			$parts = explode ( '--', $_COOKIE [$key] );
			return $parts [0];
		} else
			return false;
	}
	/**
	 * Destroys the specified cookie
	 * 
	 * @return void
	 * @param string $key        	
	 */
	public static function destroyCookie($key) {
		setcookie ( $key, NULL, time () - 3600, '/' );
		return;
	}
	// End of cookie protection section //
	// ******************************** //
	
	// CSRF protection section //
	// *********** *********** //
	
	/**
	 * Generates a random token
	 * 
	 * @return string(32)
	 */
	private static function csrf_token() {
		return md5 ( uniqid ( rand (), TRUE ) );
	}
	/**
	 * Puts a generated string and generation time into the session
	 * 
	 * @return string $token
	 * @param
	 *        	void
	 */
	private static function create_csrf_token() {
		$token = self::csrf_token ();
		$_SESSION ['csrf_token'] = $token;
		$_SESSION ['csrf_token_time'] = time ();
		return $token;
	}
	
	/**
	 * Returns an input tag with the generated token
	 * 
	 * @return string
	 * @param
	 *        	void
	 */
	public static function csrf_token_tag() {
		$token = self::create_csrf_token ();
		return "<input type=\"hidden\" name=\"csrf_token\" value=\"" . $token . "\">";
	}
	/**
	 * Checks whether the csrf_token in the session and in the post field are the same
	 * 
	 * @return boolean
	 * @param
	 *        	void
	 */
	public static function is_csrf_token_valid() {
		if (isset ( $_POST ['csrf_token'] )) {
			$user_token = $_POST ['csrf_token'];
			$server_token = $_SESSION ['csrf_token'];
			if ($user_token === $server_token)
				return TRUE;
		} else
			return FALSE;
	}
	/**
	 * Checks whether the csrf_token_time present in the session is recent or not
	 * 
	 * @return boolean
	 * @param
	 *        	void
	 */
	public static function is_csrf_token_recent() {
		$max_elapsed_time = Security_Config::$csrf_token_lifetime;
		$token_time = $_SESSION ['csrf_token_time'];
		if (($token_time + $max_elapsed_time) > time ()) {
			return TRUE;
		} else
			return FALSE;
	}
	// End of CSRF Protection section //
	// ********************************** //
	
	/**
	 * Gets a string from POST superglobal
	 * 
	 * @return string or NULL
	 * @param string $key        	
	 *
	 */
	public static function getfromPost($key) {
		// Checks whether the given key exist then return it or return null if not
		if (array_key_exists ( $key, $_POST )) {
			return $_POST [$key];
		} else
			return NULL;
	}
}

// End of Security class //
// *********************** //

define ( 'IS_BANNED', - 1 );
define ( 'IS_GUEST', 0 );
define ( 'IS_MEMBER', 0 );
define ( 'IS_MODERATOR', 0 );
define ( 'IS_ADMIN', 0 );

// Our authorization class
class Authorize {
	protected static $auth_level;
	
	// Sets our authorization level
	public static function set_auth_level($userid = '') {
		if ($userid == '') {
			self::$auth_level = IS_GUEST;
			return;
		}
		// Call our user model to retreive the authorization level
		self::$auth_level = User::getAuthLevel ( $userid );
		return;
	}
	// Checks the database whether we permit to see the selected content
	// @expect int
	// @return boolean
	public static function is_permit_to_see($section) {
		$db = new Database ();
		$query = 'SELECT COUNT(privileges) AS privileges FROM authorize WHERE  auth_level <= \'' . self::$auth_level . '\' AND section = \'' . $section . '\'';
		foreach ( $db->query ( $query ) as $result ) {
			if ($result ['privileges'] > 0)
				return TRUE;
		}
		return FALSE;
	}
}
// End of our authorization class

/**
 * Our session handling class
 *
 * @author Tacsiazuma
 * @staticvar $salt
 * @staticvar $db
 * @staticvar $connect
 * @staticvar $result
 * @staticvar $valid_session_id
 * @static validateSessionId
 * @static generateSessionId
 * @static keepMeLogged
 *        
 *        
 */
class SessionManager {
	protected static $salt;
	protected static $db;
	protected static $connect;
	protected static $result;
	protected static $valid_session_id;
	function __construct() {
		if (! is_writable ( session_save_path () )) {
			CMSException ( 3002 );
		}
		self::$salt = SALT;
	}
	
	/**
	 * Validates our Session ID
	 * Checks whether its length matches and the userid key is present or throw an exception
	 * Checks the database looking in the user_sessions table for the sessionid and
	 *
	 * @throws Exception
	 * @return int self::$result['u_id']
	 */
	static function validateSessionID() {
		
		// Connect to the database
		$db = new Database ();
		
		// Figure out that we got a USERID paired to our session
		// If we got, then we check its format. If wrong then throw it!
		
		if ((strlen ( session_id () ) != 32) && isset ( $_SESSION ['userid'] )) {
			throw new Exception ( "The session ID is malformed" );
		}
		
		// Dig deeper into our sessions, fetch the row containing our session ID
		$query = "SELECT * FROM user_sessions WHERE session_id = '" . session_id () . "'";
		foreach ( $db->query ( $query ) as $result ) {
			self::$result = $result;
			self::$valid_session_id = md5 ( $result ['u_id'] . $_SERVER ['HTTP_USER_AGENT'] . self::$salt . $_SERVER ['REMOTE_ADDR'] . $result ['created'] );
		}
		
		// Check whether our sessionID is valid if an userid index is present
		// If not valid, drop an exception
		if (session_id () != self::$valid_session_id && isset ( $_SESSION ['userid'] )) {
			self::DestroySession ();
		}
		
		// Destroy our session if its past the time limit
		
		if (! is_null ( self::$result ['u_id'] ) && self::$result ['created'] + 1200 < time () && ! self::keepMeLogged ()) {
			self::DestroySession ();
			
			// Update our session if its recent
		} elseif (! is_null ( self::$result ['u_id'] ) && self::$result ['created'] + 1200 > time ()) {
			self::updateSession ();
		}
		// Return the userid
		RETURN self::$result ['u_id'];
	}
	
	/**
	 * Checks whether our Session cookie is present or not
	 *
	 * @param
	 *        	void
	 * @return boolean
	 */
	static function keepMeLogged() {
		return isset ( $_COOKIE [session_name ()] );
	}
	
	/**
	 * We generate our md5 hashed sessionid which consists from some environmental variables and salt
	 *
	 * @param string $userid        	
	 * @param int $start_time        	
	 * @return string $new_session_id
	 *        
	 *        
	 */
	static function generateSessionID($userid, $start_time) {
		$new_session_id = md5 ( $userid . $_SERVER ['HTTP_USER_AGENT'] . self::$salt . $_SERVER ['REMOTE_ADDR'] . $start_time );
		return $new_session_id;
	}
	
	/**
	 * Connects to the database, destroys the previous session and writes
	 * our new session into the database
	 * 
	 * @param string $userid        	
	 * @param boolean $keep_me_logged        	
	 * @var object $db
	 * @var string $query
	 * @var int $start_time
	 * @return boolean
	 *
	 */
	static function registerSession($userid, $keep_me_logged) {
		$start_time = time ();
		$db = new Database ();
		
		// Disconnect our user from other devices.
		self::DestroySession ( $userid );
		$query = "INSERT INTO user_sessions (`session_id`,`u_id`,`ip_address`,`user_agent`,`created`, `last_modified`) VALUES
 ('" . self::generateSessionID ( $userid, $start_time ) . "','" . $userid . "','" . $_SERVER ['REMOTE_ADDR'] . "','" . $_SERVER ['HTTP_USER_AGENT'] . "','" . $start_time . "','" . $start_time . "')";
		$db->Execute ( $query );
		$_SESSION ['userid'] = $userid;
		
		session_id ( self::generateSessionID ( $userid, $start_time ) );
		
		// If we checked to keep us logged in then we create a cookie which holds for a year
		// If we not, then we create a cookie which holds as long as the session.
		if ($keep_me_logged == TRUE) {
			setcookie ( session_name (), session_id (), time () + 3600 * 24 * 365, '/' );
		} else
			setcookie ( session_name (), session_id (), 0, '/' );
		return TRUE;
	}
	/**
	 * Update our user_session record, sets the last_modified to the current time
	 * 
	 * @var object $db
	 * @param
	 *        	void
	 * @var integer $start time
	 * @return void
	 */
	static function updateSession() {
		$db = new Database ();
		
		$start_time = time ();
		$query = "UPDATE user_sessions SET last_modified = '" . $start_time . "' WHERE session_id='" . session_id () . "'";
		$db->Execute ( $query );
		return;
	}
	
	/**
	 * Populates our session with variables
	 *
	 * @var $SESSION['userid']
	 * @var $SESSION['permissions']
	 * @return void
	 * @param
	 *        	void
	 *        	
	 *        	
	 */
	static function PopulateSession($userid) {
		$db = new Database ();
		
		$query = "SELECT * FROM users WHERE `id` = '" . PIE_Security::sanitizeString ( $userid ) . "' LIMIT 1";
		try {
			foreach ( $db->query ( $query ) as $resultset ) {
				$_SESSION ['userid'] = $userid;
				// @ TODO delete it?
				$_SESSION ['permissions'] = $resultset ['auth'];
			}
		} catch ( Exception $e ) {
		}
	}
	
	/**
	 * Destroys our session
	 *
	 * @return void
	 * @param string $userid        	
	 * @var object $db
	 * @var string $query
	 * @throws Exception
	 */
	static function DestroySession($userid = '') {
		$db = new Database ();
		// If the given userid is not empty, then we delete using it
		if ($userid != '') {
			$query = "DELETE FROM user_sessions WHERE `u_id`='" . $userid . "'";
			// If its empty then we delete using the session id
		} else
			$query = "DELETE FROM user_sessions WHERE `session_id`='" . session_id () . "'";
		
		$db->Execute ( $query );
		if ($db->Errorcode () != 0) {
			throw new Exception ( 'Cannot access the database with query:' . $db->Errorcode () . ' at file <b>' . __FILE__ . '</b> at line <b>' . __LINE__ . '</b>' );
		}
		// Unset, destroy, writeclose the session and unset the session cookie too
		session_unset ();
		session_destroy ();
		session_write_close ();
		setcookie ( session_name (), '', time () - 3600, '/' );
	}
}
// End of session control section   //	
// *********************************  //
