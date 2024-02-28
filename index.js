const express = require("express");
const cors = require("cors");
const app = express();
const bcrypt = require("bcrypt");
require("dotenv").config();
const jwt = require("jsonwebtoken");
const port = process.env.PORT || 5000;
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");

// middleware
app.use(cors());
app.use(express.json());

// mongo db
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.ectfhk2.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// verify jwt
const verifyJWT = (req, res, next) => {
  const authorization = req.headers.authorization;

  if (!authorization) {
    return res
      .status(401)
      .send({ error: true, message: "unauthorized access" });
  }

  // it will carry bearer token thats why it has to split
  const token = authorization.split(" ")[1];

  jwt.verify(token, process.env.JWT_ACCESS_TOKEN, (err, decoded) => {
    if (err) {
      return res
        .status(401)
        .send({ error: true, message: "unauthorized access" });
    }

    req.decoded = decoded;
    next();
  });
};

const generateTransactionID = () => {
  const randomNumber = Math.floor(10000 + Math.random() * 90000);
  const trxId = "TRX-01-" + randomNumber;
  return trxId;
};

app.get("/", (req, res) => {
  res.send("Pocket Pal server is running");
});

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});
async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    await client.connect();

    const userCollection = client.db("pocketPalDB").collection("users");
    const sendCollection = client.db("pocketPalDB").collection("send");

    app.post("/users/auth", async (req, res) => {
      const { mail_phone, pin } = req.body;
      const result = await userCollection.findOne({
        $or: [{ email: mail_phone }, { phone: mail_phone }],
      });
      if (result === null) {
        res.status(401).send({ message: "User Not Found" });
        return;
      }

      const isMatch = await bcrypt.compare(pin, result.pin);

      if (!isMatch) {
        res.status(401).send({ message: "Invalid PIN" });
      } else {
        res.send(result);
      }
    });

    app.post("/insert-user", async (req, res) => {
      const data = req.body;
      const query = {
        $or: [{ email: data.email }, { phone: data.phone }, { nid: data.nid }],
      };
      const findRes = await userCollection.findOne(query);
      if (findRes) {
        res.status(402).send({ message: "User has already an account" });
        return;
      }

      const hashedPassword = await bcrypt.hash(data.pin, 10);
      data.pin = hashedPassword;
      const result = await userCollection.insertOne(data);
      res.send(result);
    });

    app.get("/user/admin/:email", verifyJWT, async (req, res) => {
      const email = req.params.email;

      if (req.decoded.email !== email) {
        res.send({ admin: false });
      }
      const query = { email: email };
      const user = await userCollection.findOne(query);
      const result = { admin: user?.role === "admin" };
      res.send(result);
    });

    app.get("/user/agent/:email", verifyJWT, async (req, res) => {
      const email = req.params.email;

      if (req.decoded.email !== email) {
        res.send({ admin: false });
      }
      const query = { email: email };
      const user = await userCollection.findOne(query);
      const isAgent = user?.role === "agent" && user?.active === "open";
      res.send({ agent: isAgent });
    });

    app.get("/user/client/:email", verifyJWT, async (req, res) => {
      const email = req.params.email;

      if (req.decoded.email !== email) {
        res.send({ admin: false });
      }
      const query = { email: email };
      const user = await userCollection.findOne(query);
      const isClient = user?.role === "user";
      res.send({ client: isClient });
    });

    app.post("/user/send-money", verifyJWT, async (req, res) => {
      const data = req.body;
      const charge = data.amount >= 100 ? 5 : 0;
      const trxId = generateTransactionID();
      const query1 = { phone: data.sender_phone };
      const result1 = await userCollection.findOne(query1);
      const prevMoney = result1.balance;
      const newBalance = prevMoney - data.amount;
      const update = { $set: { balance: newBalance } };
      const modifySender = await userCollection.updateOne(query1, update);
      const query2 = { phone: data.receiver_phone };
      const result2 = await userCollection.findOne(query2);
      const prevBalance = result2?.balance || 0;
      const updateBalance = prevBalance + data.amount;
      const update2 = { $set: { balance: updateBalance } };
      const modifyReciever = await userCollection.updateOne(query2, update2);
      const newData = {
        sender: data.sender_phone,
        reciever: data.receiver_phone,
        amount: data.amount,
        transactionId: trxId,
      };

      const res1 = await sendCollection.insertOne(newData);
      const query3 = { role: "admin" };
      const findAdmin = await userCollection.findOne(query3);
      const adminBalance = findAdmin?.balance || 0;
      const newAdminBalance = adminBalance + charge;
      const updateAdmin = { $set: { balance: newAdminBalance } };
      const lastUpdate = await userCollection.updateOne(query3, updateAdmin);
      res.send(res1);
    });

    app.get("/transaction/:email", async (req, res) => {
      const email = req.params.email;
      const query = { email: email };
      const find = await sendCollection.find(query).toArray();
      res.send(find);;
    });
    
    //jwt access token
    app.post("/jwt", (req, res) => {
      const user = req.body;
      const token = jwt.sign(user, process.env.JWT_ACCESS_TOKEN, {
        expiresIn: "6h",
      });
      res.send({ token });
    });

    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

app.listen(port, () => {
  console.log(`App listening on port ${port}`);
});
