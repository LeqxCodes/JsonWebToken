import * as express from "express";
import * as bodyparser from "body-parser";

const uuid = require("uuidv4");
const jwt = require("jsonwebtoken");
const CryptoJS = require("crypto-js");
const key: string = "wn5ndJfLXR4lgPVK7VhcpG73TibKSiYUaRlSvRUw";

//Links
//JWT: https://www.npmjs.com/package/jsonwebtoken
//UUIDV4: https://www.npmjs.com/package/uuidv4
//CRYPTO-JS https://www.npmjs.com/package/crypto-js

export class Server {
  public app: express.Application;

  //#region Constructor

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

  private dataEndPoint(req: express.Request, res: express.Response) {
    let auth: string = req.headers.authorization as string;
    let bearer: string = req.query.bearer as string;
    let token: string = auth ? auth : bearer || null;

    if (token) {
        let decoded = this.decodeToken(token);
        if(decoded){
            res.send("Here is your data.");
        }
        else{
            res.send(401).send();
        }
    } else {
      res.status(400).send();
    }
  }

  //#endregion EndPoints

  //#region Custom jwt

  //https://www.jonathan-petitcolas.com/2014/11/27/creating-json-web-token-in-javascript.html
  private createCustomToken(user: User): string {
    if (!user || !user.name || !user.hash) {
      throw new Error("Invalid user!");
    }

    let encoded = this.buildToken({ role: user.role, uuid: user.uuid });
    return this.signToken(encoded);
  }

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

  private signToken(token: string): string {
    var signature = CryptoJS.HmacSHA256(token, key);
    signature = this.base64url(signature);

    return token + "." + signature;
  }

  //#endregion Custom jwt

  //#region jwt

  private createJwtToken(user: User): string {
    if (!user || !user.role || !user.uuid) {
      throw new Error("Invalid user!");
    }

    let result: string = jwt.sign({ role: user.role, uuid: user.uuid }, key, {
      noTimestamp: true,
    });
    return result;
  }

  private decodeToken(token: string): any {
    if (!token) {
      return null;
    }

    try{

        //jwt.decode(); -- Returns the decoded payload without verifying if the signature is valid!
        return jwt.verify(token, key);
    }
    catch(ex){
        return null;
    }

  }

  //#endregion jwt
}

class User {
  public name: string;

  public hash: string;

  public role: string;

  public uuid: string;

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

new Server();
