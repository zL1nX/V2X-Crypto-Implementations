//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
// 

package sm2_test_sign;
//
// TODO documentation
//
simple A
{
    gates:
        input in;
        output out;
}

//
// TODO documentation
//
simple B
{
    gates:
        input in;
        output out;
}

//
// TODO documentation
//
network sm2_sign
{
    submodules:
        a: A {
            @display("p=73,93");
        }
        b: B {
            @display("p=210,93");
        }
    connections:
        a.out --> b.in;
        b.out --> a.in;
}

