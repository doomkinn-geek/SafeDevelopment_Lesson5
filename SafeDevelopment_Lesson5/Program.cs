using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SafeDevelopment_Lesson5
{
    internal class Program
    {
        static void Main(string[] args)
        {
            while (true)
            {
                Console.WriteLine("~~ Центр генерации сертификатов ~~~\n");
                Console.WriteLine("1. Создать корневой сертификат");
                Console.WriteLine("2. Создать сертификат");
                Console.Write("Выберите подпрограмму (0 - завершение работы приложения): ");
                if (int.TryParse(Console.ReadLine(), out int no))
                {
                    switch (no)
                    {
                        case 0:
                            Console.WriteLine("Завершение работы приложения.");
                            Console.ReadKey();
                            return;
                        case 1:                            
                            break;
                        case 2:                            
                            break;
                        default:
                            Console.WriteLine("Некорректный номер подпрограммы. Пожалуйста, повторите ввод.");
                            break;
                    }
                }
                else
                    Console.WriteLine("Некорректный номер подпрограммы. Пожалуйста, повторите ввод.");
            }
        }
    }
}
