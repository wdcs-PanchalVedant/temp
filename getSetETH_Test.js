const {
    expect
} = require("chai");

describe('getSetETh Contract', () => {

    let ownerWallet, wallet2, wallet3, wallet4, contarct, tempContract;

    describe('Deploying Contract', () => {
        beforeEach(async () => {
            [ownerWallet, wallet2, wallet3] = await ethers.getSigners();
            tempContract = await ethers.getContractFactory("getSetETH");
            contarct = await tempContract.deploy();
        })

        it('View Methods Should Work', async () => {
            console.log(await contarct.totalFunds());
        })
    })

    describe("Main Methods", () => {
        it("Diposit Methods Should Work", async () => {
         await contarct.deposit(wallet2.address,{value:"1000000000000000000"});
         expect(await contarct.totalFunds()).to.equal("1000000000000000000");
         expect(await contarct.depositsOf(wallet2.address)).to.equal("1000000000000000000");
        })
    })

})