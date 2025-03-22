const fs = require("fs/promises");
const path = require("path");

const readline = require("readline/promises").createInterface({
  input: process.stdin,
  output: process.stdout,
});

const sqlite3 = require(require.resolve("sqlite3"));
const sqlite = require("sqlite");

const { ArgumentParser } = require("argparse");
const parser = new ArgumentParser({
  description: "SQLite3 console",
});
parser.add_argument("-f", "--file", {
  help: "path to the SQLite3 database file",
  type: "str",
});

async function main() {
  const file = parser.parse_args().file;
  const backup = path.basename(file) + ".bak";

  if (
    (
      await readline.question(
        "Do you want to backup the database file? [YES/no] "
      )
    ).toLowerCase() !== "no"
  ) {
    await fs.copyFile(file, backup, fs.constants.COPYFILE_EXCL);
  }

  const db = await sqlite.open({
    filename: file,
    driver: sqlite3.Database,
  });

  const cleanup = async () => {
    readline.close();
    await db.close();
    console.log("DB has been shut down");
    process.exit();
  };

  readline.on("SIGINT", () => readline.close());
  readline.on("close", cleanup);

  let query = "";

  while (true) {
    const input = await readline.question(
      query.length === 0 ? "sqlite3> " : "       > "
    );
    if (!input) {
      continue;
    }

    const end = input.indexOf(";");
    query += end === -1 ? input + "\n" : input.slice(0, end + 1);
    if (end === -1) {
      continue;
    } else if (query.toLowerCase().trim() === "exit;") {
      break;
    }

    readline.pause();
    console.log(query);
    console.log("-".repeat(30));

    try {
      const res = await db.all(query);
      console.log(res);
    } catch (e) {
      console.error(e);
    }
    query = "";
  }

  await cleanup();
}

main();
