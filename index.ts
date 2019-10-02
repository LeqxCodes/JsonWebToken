import * as express from "express";
import * as bodyparser from "body-parser";

const uuid = require("uuidv4");
const jwt = require("jsonwebtoken");
const CryptoJS = require("crypto-js");
// Key for signing a JWT
const key: string = "wn5ndJfLXR4lgPVK7VhcpG73TibKSiYUaRlSvRUw";

//Links
//JWT: https://www.npmjs.com/package/jsonwebtoken
//UUIDV4: https://www.npmjs.com/package/uuidv4
//CRYPTO-JS https://www.npmjs.com/package/crypto-js

/**
 * The webserver
 *
 * @export
 * @class Server
 */
export class Server {
  /**
   * The express app of the server
   *
   * @type {express.Application}
   * @memberof Server
   */
  public app: express.Application;

  //#region Constructor

  /**
   *Creates an instance of Server.
   * @memberof Server
   */
  constructor() {
    //Setup
    this.app = express();
    this.app.use(bodyparser.json());
    //Middleware
    this.app.use(this.logRequests.bind(this));
    //Endpoints
    this.app.post("/api/login", this.loginEndPoint.bind(this));
    this.app.get("/api/data", this.dataEndPoint.bind(this));
    //Port
    this.app.listen(5000);
    //Bindings
    this.createJwtToken.bind(this);
    this.createCustomToken.bind(this);
    this.base64url.bind(this);
    this.buildToken.bind(this);
    this.signToken.bind(this);
  }

  //#endregion Constructor

  //#region  Middleware

  /**
   * Middleware to log all incoming requests
   *
   * @private
   * @param {express.Request} req
   * @param {express.Response} res
   * @param {express.NextFunction} next
   * @memberof Server
   */
  private logRequests(
    req: express.Request,
    res: express.Response,
    next: express.NextFunction
  ) {
    console.log(req.url);
    next();
  }

  //#endregion Middleware

  //#region EndPoints

  /**
   * The login REST API endpoint
   *
   * @private
   * @param {express.Request} req
   * @param {express.Response} res
   * @memberof Server
   */
  private loginEndPoint(req: express.Request, res: express.Response) {
    let user = new User(req.body.name, req.body.hash);

    console.log(JSON.stringify(user));
    //Zugangsdaten wurden überprüft und sind korrekt ;)

    try {
      let token = this.createJwtToken(user);
      let customToken = this.createCustomToken(user);
      console.log("Custom: " + token);
      console.log("JWT: " + customToken);

      let decoded = this.decodeToken(token);
      let customDecoded = this.decodeToken(customToken);
      console.log("Custom: " + JSON.stringify(customDecoded));
      console.log("JWT: " + JSON.stringify(decoded));
    } catch (ex) {
      console.log(ex);
    }

    res.status(200).send(this.createJwtToken(user));
  }

  /**
   * The data REST API Endpoint
   *
   * @private
   * @param {express.Request} req
   * @param {express.Response} res
   * @memberof Server
   */
  private dataEndPoint(req: express.Request, res: express.Response) {
    let auth: string = req.headers.authorization as string;
    let bearer: string = req.query.bearer as string;
    let token: string = auth ? auth : bearer || null;

    if (token) {
      let decoded = this.decodeToken(token);
      if (decoded) {
        res.send("Here is your data.");
      } else {
        res.send(401).send();
      }
    } else {
      res.status(400).send();
    }
  }

  //#endregion EndPoints

  //#region Custom jwt

  /**
   * Create a custom JWT
   * https://www.jonathan-petitcolas.com/2014/11/27/creating-json-web-token-in-javascript.html
   * @private
   * @param {User} user
   * @returns {string}
   * @memberof Server
   */
  private createCustomToken(user: User): string {
    if (!user || !user.name || !user.hash) {
      throw new Error("Invalid user!");
    }

    let encoded = this.buildToken({ role: user.role, uuid: user.uuid });
    return this.signToken(encoded);
  }
  /**
   * Encode a string to base64
   *
   * @private
   * @param {string} source
   * @returns {string}
   * @memberof Server
   */
  private base64url(source: string): string {
    // Encode in classical base64
    let encodedSource = CryptoJS.enc.Base64.stringify(source);

    // Remove padding equal characters
    encodedSource = encodedSource.replace(/=+$/, "");

    // Replace characters according to base64url specifications
    encodedSource = encodedSource.replace(/\+/g, "-");
    encodedSource = encodedSource.replace(/\//g, "_");

    return encodedSource;
  }

  /**
   * Create a custom JWT
   * self-implemented
   * @private
   * @param {*} data The data to store within the token
   * @returns {string} The JWT as string
   * @memberof Server
   */
  private buildToken(data: any): string {
    const header = {
      alg: "HS256",
      typ: "JWT"
    };

    let stringifiedHeader = CryptoJS.enc.Utf8.parse(JSON.stringify(header));
    let encodedHeader = this.base64url(stringifiedHeader);

    let stringifiedData = CryptoJS.enc.Utf8.parse(JSON.stringify(data));
    let encodedData = this.base64url(stringifiedData);

    return encodedHeader + "." + encodedData;
  }
  /**
   * Sign a custom JWT
   * self-implemented
   * @private
   * @param {string} token
   * @returns {string}
   * @memberof Server
   */
  private signToken(token: string): string {
    var signature = CryptoJS.HmacSHA256(token, key);
    signature = this.base64url(signature);

    return token + "." + signature;
  }

  //#endregion Custom jwt

  //#region jwt

  /**
   * Create a signed JWT using jsonwebtoken (npm package)
   *
   * @private
   * @param {User} user
   * @returns {string}
   * @memberof Server
   */
  private createJwtToken(user: User): string {
    if (!user || !user.role || !user.uuid) {
      throw new Error("Invalid user!");
    }

    let result: string = jwt.sign({ role: user.role, uuid: user.uuid }, key, {
      noTimestamp: true
    });
    return result;
  }

  /**
   * Decode a JWT using jsonwebtoken (npm package)
   *
   * @private
   * @param {string} token
   * @returns {*}
   * @memberof Server
   */
  private decodeToken(token: string): any {
    if (!token) {
      return null;
    }

    // Never use jwt.decode() !!!!
    try {
      //jwt.decode(); -- Returns the decoded payload without verifying if the signature is valid!
      return jwt.verify(token, key);
    } catch (ex) {
      return null;
    }
  }

  //#endregion jwt
}

/**
 * Sample user Class
 *
 * @class User
 */
class User {
  /**
   * The name of the user
   *
   * @type {string}
   * @memberof User
   */
  public name: string;
  /**
   * The hash of the user
   *
   * @type {string}
   * @memberof User
   */
  public hash: string;
  /**
   * The role of the user
   *
   * @type {string}
   * @memberof User
   */
  public role: string;
  /**
   * The uinque Id of the user
   *
   * @type {string}
   * @memberof User
   */
  public uuid: string;

  /**
   *Creates an instance of User.
   * @param {string} name The name
   * @param {string} hash The hash
   * @memberof User
   */
  constructor(name: string, hash: string) {
    if (name === "bob") {
      this.role = "admin";
    } else {
      this.role = "user";
    }
    this.uuid = uuid();
    this.name = name;
    this.hash = hash;
  }
}

/**
 * Initialize and start the server.
 */
new Server();
